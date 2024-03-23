#include "drogon-user/User.hpp"
#include "drogon/Cookie.h"
#include "drogon/HttpAppFramework.h"
#include "drogon/HttpFilter.h"
#include "drogon/HttpRequest.h"
#include "drogon/HttpResponse.h"
#include "drogon/HttpTypes.h"
#include "drogon/WebSocketConnection.h"
#include "drogon/utils/FunctionTraits.h"
#include "drogon/utils/Utilities.h"
#include "trantor/utils/ConcurrentTaskQueue.h"
#include <any>
#include <cstddef>
#include <cstdint>
#include <json/value.h>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#ifdef ENABLE_OFFLINE_CALLBACK
#include <vector>
#endif

using namespace drogon;
using std::string;
using std::string_view;
using std::shared_ptr;

namespace drogon::user
{
	extern double userCacheTimeout_;

#ifdef ENABLE_OFFLINE_CALLBACK
	extern std::vector<OfflineUserCallback> offlineUserCallbacks_;
#endif
}

static string idCookieKey_ = "ID";
static uint8_t idUnencodedLen_, idLen_;
static uint16_t forkedIdLen_;
static int maxAge_ = 86400;
static Cookie::SameSite sameSite_ = Cookie::SameSite::kStrict;
static bool
	httpOnly_ = true,
	secure_ = true;
static user::IdGenerator idGenerator_;
static user::IdEncoder idEncoder_;
static user::DatabaseSessionValidationCallback sessionValidationCallback_;
static user::MemorySessionVerificationCallback sessionVerificationCallback_;
static user::DatabaseLoginWriteCallback loginWriteCallback_;
static user::IdFormatValidator idFormatValidator_;
static user::DatabasePostValidationCallback postValidationCallback_;
static user::ExtraContextGenerator extraContextGenerator_;
static bool hasLoginRedirect_ = false, hasLoggedInRedirect_ = false;
static string loginPageUrl_, loggedInPageUrl_;

static trantor::ConcurrentTaskQueue taskQueue_(std::thread::hardware_concurrency(), "");

void user::configure(
	string_view idCookieKey,
	int idCookieMaxAge,
	Cookie::SameSite sameSite,
	bool httpOnly,
	bool secure,
	double userCacheTimeout,
	uint8_t idUnencodedLen,
	uint8_t idEncodedLen,
	IdGenerator&& idGenerator,
	IdEncoder&& idEncoder)
{
	idCookieKey_ = idCookieKey;
	idUnencodedLen_ = idUnencodedLen ? idUnencodedLen : 16;
	idLen_ = idEncodedLen ? idEncodedLen : utils::base64EncodedLength(idUnencodedLen_, false);
	forkedIdLen_ = idLen_ * 2;
	maxAge_ = idCookieMaxAge;
	sameSite_ = sameSite;
	httpOnly_ = httpOnly;
	secure_ = secure;
	userCacheTimeout_ = userCacheTimeout;
	idGenerator_ = std::move(
		idGenerator ? idGenerator : [](string& id) -> void
		{
			utils::secureRandomBytes(id.data(), idUnencodedLen_);
		}
	);
	idEncoder_ = std::move(
		idEncoder ? idEncoder : [](string& idUnencoded) -> void
		{
			idUnencoded = utils::base64Encode(idUnencoded, true, false);
		}
	);
}
static size_t authorizationHeaderMinLen_;
static constexpr string_view
	authorizationHeaderPrefix = "Basic ",
	authorizationHeaderPrefix2 = "basic ";
static constexpr uint8_t authorizationHeaderPrefixLen = authorizationHeaderPrefix.size();
void user::configureDatabase(
	DatabaseLoginValidationCallback&& loginValidationCallback,
	DatabaseSessionValidationCallback&& sessionValidationCallback,
	DatabaseLoginWriteCallback&& loginWriteCallback,
	DatabaseSessionInvalidationCallback&& sessionInvalidationCallback,
	MemorySessionVerificationCallback sessionVerificationCallback,
	UserLogoutNotifyCallback userLogoutNotifyCallback,
	IdFormatValidator idFormatValidator,
	ExtraContextGenerator extraContextGenerator,
	DatabasePostValidationCallback postValidationCallback,
	uint8_t minimumIdentifierLength,
	uint8_t maximumIdentifierLength,
	uint8_t minimumPasswordLength,
	uint8_t maximumPasswordLength,
	const string& loginValidationEndpoint,
	const string& logoutEndpoint,
	const string& loginPageUrl,
	const string& loggedInPageUrl)
{
	sessionValidationCallback_ = std::move(sessionValidationCallback);
	sessionVerificationCallback_ = std::move(sessionVerificationCallback);
	loginWriteCallback_ = std::move(loginWriteCallback);
	idFormatValidator_ = idFormatValidator;
	extraContextGenerator_ = extraContextGenerator;
	postValidationCallback_ = postValidationCallback;
	loginPageUrl_ = std::move(loginPageUrl);
	loggedInPageUrl_ = std::move(loggedInPageUrl);
	hasLoginRedirect_ = !loginPageUrl_.empty();
	hasLoggedInRedirect_ = !loggedInPageUrl_.empty();

	authorizationHeaderMinLen_ =
		authorizationHeaderPrefixLen +
		utils::base64EncodedLength(
			minimumIdentifierLength + 1/* : */ + minimumPasswordLength
		);

	// Login endpoint
	app().registerHandler(loginValidationEndpoint,
		[
			minimumIdentifierLength,
			maximumIdentifierLength,
			minimumPasswordLength,
			maximumPasswordLength,
			loginValidationCallback = std::move(loginValidationCallback)
		]
		(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr&)>&& callback) -> void
	{
		string_view authorizationPayload = req->getHeader("Authorization");
		auto len = authorizationPayload.size();
		if(len < authorizationHeaderMinLen_)
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		if(!authorizationPayload.starts_with(authorizationHeaderPrefix) &&
			!authorizationPayload.starts_with(authorizationHeaderPrefix2))
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		authorizationPayload.remove_prefix(authorizationHeaderPrefixLen);

		string payload = utils::base64Decode(authorizationPayload);
		auto colonIdx = payload.find(':');
		if(colonIdx == string::npos)
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		// colonIdx = identifierLen
		if(colonIdx < minimumIdentifierLength || colonIdx > maximumIdentifierLength)
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		authorizationPayload = payload; // view
		string_view identifier = authorizationPayload.substr(0, colonIdx);

		authorizationPayload.remove_prefix(colonIdx + 1); // authorizationPayload = password
		len = authorizationPayload.size();
		if(len < minimumPasswordLength)
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		if(len > maximumPasswordLength) // truncate the password if it exceeds the limit
			authorizationPayload.remove_suffix(len - maximumPasswordLength);

		// ^ Length: OK

		std::any extraContext;
		if(extraContextGenerator_)
			extraContext = extraContextGenerator_(req);

		taskQueue_.runTaskInQueue(
		[
			req = std::move(req),
			identifier,
			password = std::move(authorizationPayload), // authorizationPayload = password
			extraContext = std::move(extraContext),
			callback = std::move(callback),
			loginValidationCallback = std::move(loginValidationCallback)
		]()
		{
			auto data = loginValidationCallback(identifier, password, extraContext);
			if(!data.has_value()) // Incorrect identifier or password
			{
				callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
				return;
			}

			// ^ Validation: OK

			string sessionId = generateId();

			// ^ ID Generation: OK

			{
				auto resp = HttpResponse::newHttpResponse(k200OK, CT_NONE);
				generateIdFor(resp, sessionId);
				callback(resp);
			}

			// ^ Response: OK

			UserPtr user = std::move(
				User::create(
					std::move(sessionId)
				)
			);
			if(postValidationCallback_)
				postValidationCallback_(user, data);

			// ^ Memory Cache: OK

			loginWriteCallback_(user->id(), identifier, data);

			// ^ Database: OK
		});
	},
	{
		HttpMethod::Post
	});

	// Logout endpoint
	app().registerHandler(logoutEndpoint,
		[
			sessionInvalidationCallback = std::move(sessionInvalidationCallback),
			userLogoutNotifyCallback = std::move(userLogoutNotifyCallback)
		](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr&)>&& callback) -> void
	{
		taskQueue_.runTaskInQueue(
		[
			req = std::move(req),
			callback = std::move(callback),
			sessionInvalidationCallback = std::move(sessionInvalidationCallback),
			userLogoutNotifyCallback = std::move(userLogoutNotifyCallback)
		]()
		{
			auto id = user::getId(req);
			if(!sessionInvalidationCallback(id))
			{
				callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
				return;
			}

			// ^ Database and Validation: OK

			{
				auto resp = HttpResponse::newHttpResponse(k200OK, CT_NONE);
				removeIdFor(resp);
				callback(resp);
			}

			// ^ Response: OK

			if(UserPtr user = User::get(id))
			{
				if(userLogoutNotifyCallback)
					userLogoutNotifyCallback(user);

				user->forceClose();
			}

			// ^ Close Connections: OK
		});
	},
	{
		HttpMethod::Delete
	});
}

#ifdef ENABLE_OFFLINE_CALLBACK
void user::registerOfflineUserCallback(OfflineUserCallback&& cb)
{
	offlineUserCallbacks_.push_back(std::move(cb));
}
#endif

string user::generateId()
{
	string id;
	id.reserve(idLen_);
	id.resize(idUnencodedLen_);
	idGenerator_(id);
	idEncoder_(id);
	return id;
}

void user::generateIdFor(const HttpResponsePtr& resp, const string& id)
{
	Cookie cookie(idCookieKey_, id);
	cookie.setPath("/");
	cookie.setMaxAge(maxAge_);
	cookie.setSameSite(sameSite_);
	cookie.setHttpOnly(httpOnly_);
	cookie.setSecure(secure_);
	resp->addCookie(std::move(cookie));
}

void user::removeIdFor(const HttpResponsePtr& resp)
{
	Cookie cookie(idCookieKey_, "");
	cookie.setPath("/");
	cookie.setMaxAge(0);
	cookie.setSameSite(sameSite_);
	cookie.setHttpOnly(httpOnly_);
	cookie.setSecure(secure_);
	resp->addCookie(std::move(cookie));
}

const string& user::getIdRef(const HttpRequestPtr& req)
{
	return req->getCookie(idCookieKey_);
}



/* Security */

namespace drogon::user::filter
{
	namespace api
	{
		/// Extends the lifespan of the user object in memory if it exists
		/// on every hit to this filter
		class LoggedIn : public HttpFilter<LoggedIn>
		{
		public:
			void doFilter(const HttpRequestPtr& req,
							FilterCallback&& fcb,
							FilterChainCallback&& fccb) override;
		};

		/// Extends the lifespan of the user object in memory if it exists
		/// on every hit to this filter
		class UnloggedIn : public HttpFilter<UnloggedIn>
		{
		public:
			void doFilter(const HttpRequestPtr& req,
							FilterCallback&& fcb,
							FilterChainCallback&& fccb) override;
		};
	}

	namespace page
	{
		/// Extends the lifespan of the user object in memory if it exists
		/// on every hit to this filter
		class LoggedIn : public HttpFilter<LoggedIn>
		{
		public:
			void doFilter(const HttpRequestPtr& req,
							FilterCallback&& fcb,
							FilterChainCallback&& fccb) override;
		};

		/// Extends the lifespan of the user object in memory if it exists
		/// on every hit to this filter
		class UnloggedIn : public HttpFilter<UnloggedIn>
		{
		public:
			void doFilter(const HttpRequestPtr& req,
							FilterCallback&& fcb,
							FilterChainCallback&& fccb) override;
		};
	}
}

void drogon::user::loggedInFilter(
	const HttpRequestPtr& req,
	std::function<void (string&& overriddenId)>&& positiveCallback,
	std::function<void ()>&& negativeCallback,
	bool checkIndexHtmlOnly)
{
	/*if(checkIndexHtmlOnly) // TODO:
	{
		string_view path = req->path();
		if()
		positiveCallback();
		return;
	}*/

	string_view id = user::getId(req);
	bool hasFork;
	if(id.size() != idLen_ && !(hasFork = (id.size() == forkedIdLen_)))
	{
		if(negativeCallback)
			negativeCallback();
		else
			positiveCallback("");
		return;
	}

	string_view sessionId;
	if(idFormatValidator_)
	{
		if(hasFork)
		{
			if(!idFormatValidator_(sessionId = id.substr(0, idLen_)) ||
				!idFormatValidator_(id.substr(idLen_)))
			{
				if(negativeCallback)
					negativeCallback();
				else
					positiveCallback("");
			}
		}
		else if(!idFormatValidator_(id))
		{
			if(negativeCallback)
				negativeCallback();
			else
				positiveCallback("");
		}
		return;
	}

	if(UserPtr user = User::get(id, true)) // Is in a room and logged in
	{
		if(positiveCallback)
		{
			string forkedId;
			if(sessionVerificationCallback_ && !hasFork)
			{
				std::any extraContext;
				if(extraContextGenerator_)
					extraContext = extraContextGenerator_(req);

				// If we were unable to verify the session, we fork
				if(!sessionVerificationCallback_(std::move(user), extraContext))
				{
					forkedId.reserve(id.size() * 2);
					forkedId = id;
					forkedId += generateId();
					User::create(std::move(forkedId));
				}
			}
			positiveCallback(std::move(forkedId));
		}
		else
			negativeCallback();
		return;
	}

	// Not in memory

	std::any extraContext;
	if(extraContextGenerator_)
		extraContext = extraContextGenerator_(req);

	taskQueue_.runTaskInQueue(
		[
			req = std::move(req),
			id = std::move(id),
			extraContext = std::move(extraContext),
			positiveCallback = std::move(positiveCallback),
			negativeCallback = std::move(negativeCallback),
			sessionId = std::move(sessionId)
		]()
	{
		bool shouldFork = false;
		auto data = sessionValidationCallback_(sessionId, extraContext, shouldFork);
		if(!data.has_value()) // Incorrect credentials
		{
			if(negativeCallback)
				negativeCallback();
			else
				positiveCallback("");
			return;
		}

		// Successful session validation

		string actualId;
		if(shouldFork && id.size() == sessionId.size()) // Suspicious session, fork the session to not disturb the real user
		{
			actualId.reserve(id.size() * 2);
			actualId = id;
			actualId += generateId();
		}
		else
			actualId = id;

		UserPtr user = std::move(
			User::create(
				string(actualId)
			)
		);
		if(postValidationCallback_)
			postValidationCallback_(std::move(user), std::move(data));

		if(positiveCallback)
			positiveCallback(std::move(actualId));
		else
			negativeCallback();
	});
}

void drogon::user::filter::api::LoggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		[fcb, fccb = std::move(fccb)](string&& overriddenId)
		{
			if(overriddenId.empty())
			{
				fccb();
				return;
			}

			auto resp = HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE); // TODO: Use a status code that is not used normally, to show partial success
			generateIdFor(resp, overriddenId);
			fcb(resp);
		},
		[fcb]()
		{
			auto resp = HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE);
			removeIdFor(resp);
			fcb(resp);
		}
	);
}

void drogon::user::filter::api::UnloggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		[fcb = std::move(fcb)](string&& overriddenId)
		{
			auto resp = HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE);
			if(!overriddenId.empty())
				generateIdFor(resp, overriddenId);
			fcb(resp);
		},
		[fccb = std::move(fccb)]()
		{
			fccb();
		}
	);
}

void drogon::user::filter::page::LoggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		[fcb, fccb = std::move(fccb)](string&& overriddenId)
		{
			if(overriddenId.empty())
			{
				fccb();
				return;
			}

			// TODO: You may want to redirect somewhere
			auto resp = HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE); // TODO: Use a status code that is not used normally, to show partial success
			generateIdFor(resp, overriddenId);
			fcb(resp);
		},
		hasLoginRedirect_ ? [fcb]()
		{
			auto resp = HttpResponse::newRedirectionResponse(loginPageUrl_);
			removeIdFor(resp);
			fcb(resp);
		} : (std::function<void ()>)nullptr,
		true
	);
}

void drogon::user::filter::page::UnloggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		hasLoggedInRedirect_ ? [fcb = std::move(fcb)](string&& overriddenId)
		{
			auto resp = HttpResponse::newRedirectionResponse(loggedInPageUrl_);
			if(!overriddenId.empty())
				generateIdFor(resp, overriddenId);
			fcb(resp);
		} : (std::function<void (string&&)>)nullptr,
		[fccb = std::move(fccb)]()
		{
			fccb();
		},
		true
	);
}



/* User Class */

User::User(string&& id) :
	id_(std::move(id)),
	conns_()
{
	enqueueForPurge(id_);
}
User::User(const string& id, const WebSocketConnectionPtr& conn, Room* room) :
	id_(id),
	conns_({
		{
			room, {
				conn
			}
		}
	})
{}

bool User::isFork() const
{
	return id_.size() > idLen_;
}

void User::setContext(const std::shared_ptr<void>& context)
{
	contextPtr_ = context;
	initCv_.notify_all();
}

void User::setContext(std::shared_ptr<void>&& context)
{
	contextPtr_ = std::move(context);
	initCv_.notify_all();
}

/// Return true if the context is set by user.
bool User::hasContext() const
{
	return (bool)contextPtr_;
}

/// Clear the context.
void User::clearContext()
{
	contextPtr_.reset();
}
