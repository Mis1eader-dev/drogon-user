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

static string
	idCookieKey_,
	userObjectKeyWithinFilters_;
static uint8_t idUnencodedLen_, idLen_;
static int maxAge_;
static Cookie::SameSite sameSite_;
static bool
	httpOnly_,
	secure_;
static user::IdGenerator idGenerator_;
static user::IdEncoder idEncoder_;
static user::DatabaseSessionValidationCallback sessionValidationCallback_;
static user::DatabaseLoginWriteCallback loginWriteCallback_;
static user::IdFormatValidator idFormatValidator_;
static user::DatabasePostValidationCallback postValidationCallback_;
static user::ExtraContextGenerator extraContextGenerator_;
static bool hasLoginRedirect_, hasLoggedInRedirect_;
static string loginPageUrl_, loggedInPageUrl_;

static trantor::ConcurrentTaskQueue taskQueue_(std::thread::hardware_concurrency(), "");

void user::configure(
	string idCookieKey,
	string userObjectKeyWithinFilters,
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
	idCookieKey_ = std::move(idCookieKey);
	userObjectKeyWithinFilters_ = std::move(userObjectKeyWithinFilters);
	idUnencodedLen_ = idUnencodedLen ? idUnencodedLen : 16;
	idLen_ = idEncodedLen ? idEncodedLen : utils::base64EncodedLength(idUnencodedLen_, false);
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
	UserLogoutNotifyCallback userLogoutNotifyCallback,
	IdFormatValidator idFormatValidator,
	ExtraContextGenerator extraContextGenerator,
	DatabasePostValidationCallback postValidationCallback,
	uint8_t minimumIdentifierLength,
	uint8_t maximumIdentifierLength,
	uint8_t minimumPasswordLength,
	uint8_t maximumPasswordLength,
	const string& loginEndpoint,
	const string& logoutEndpoint,
	string loginPageUrl,
	string loggedInPageUrl)
{
	sessionValidationCallback_ = std::move(sessionValidationCallback);
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

	app()
		// Login endpoint
		.registerHandler(loginEndpoint,
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
			]() mutable
			{
				auto data = loginValidationCallback(identifier, password, std::move(extraContext));
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

				UserPtr user = std::move(User::create(sessionId));
				if(postValidationCallback_)
					postValidationCallback_(std::move(user), data);

				// ^ Memory Cache: OK

				loginWriteCallback_(sessionId, identifier, std::move(data));

				// ^ Database: OK
			});
		},
		{
			HttpMethod::Post,
		})



		// Logout endpoint
		.registerHandler(logoutEndpoint,
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
			HttpMethod::Delete,
		})
		;
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

void user::generateIdFor(const HttpResponsePtr& resp, string id)
{
	Cookie cookie(idCookieKey_, std::move(id));
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
	std::function<void ()>&& positiveCallback,
	std::function<void (bool hasCookie)>&& negativeCallback,
	bool checkIndexHtmlOnly)
{
	/*if(checkIndexHtmlOnly) // TODO:
	{
		string_view path = req->path();
		if()
		positiveCallback();
		return;
	}*/

	auto id = user::getId(req);
	if(id.empty())
	{
		if(negativeCallback)
			negativeCallback(false);
		else
			positiveCallback();
		return;
	}

	if(id.size() != idLen_ ||
		idFormatValidator_ && !idFormatValidator_(id))
	{
		if(negativeCallback)
			negativeCallback(true);
		else
			positiveCallback();
		return;
	}

	if(UserPtr user = User::get(id, true)) // Is in a room and logged in
	{
		auto& attrs = *(req->attributes());
		attrs.insert(userObjectKeyWithinFilters_, std::move(user));

		if(positiveCallback)
			positiveCallback();
		else
			negativeCallback(true);
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
			negativeCallback = std::move(negativeCallback)
		]() mutable
	{
		auto data = sessionValidationCallback_(id, std::move(extraContext));
		if(!data.has_value()) // Incorrect credentials
		{
			if(negativeCallback)
				negativeCallback(true);
			else
				positiveCallback();
			return;
		}

		// Successful session validation

		UserPtr user = std::move(User::create(id));
		if(postValidationCallback_)
			postValidationCallback_(user, data);

		auto& attrs = *(req->attributes());
		attrs.insert(userObjectKeyWithinFilters_, std::move(user));

		if(positiveCallback)
			positiveCallback();
		else
			negativeCallback(true);
	});
}

void drogon::user::filter::api::LoggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		[req, fccb = std::move(fccb)]()
		{
			fccb();
		},
		[fcb = std::move(fcb)](bool hasCookie)
		{
			auto resp = HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE);
			if(hasCookie)
				removeIdFor(resp);
			fcb(resp);
		}
	);
}

void drogon::user::filter::api::UnloggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		[fcb = std::move(fcb)]()
		{
			fcb(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
		},
		[fccb = std::move(fccb)](bool hasCookie)
		{
			fccb();
		}
	);
}

void drogon::user::filter::page::LoggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		[fccb = std::move(fccb)]()
		{
			fccb();
		}, hasLoginRedirect_ ? [fcb = std::move(fcb)](bool hasCookie)
		{
			auto resp = HttpResponse::newRedirectionResponse(loginPageUrl_);
			if(hasCookie)
				removeIdFor(resp);
			fcb(resp);
		} : (std::function<void (bool hasCookie)>)nullptr,
		true
	);
}

void drogon::user::filter::page::UnloggedIn::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loggedInFilter(
		req,
		hasLoggedInRedirect_ ? [fcb = std::move(fcb)]()
		{
			fcb(HttpResponse::newRedirectionResponse(loggedInPageUrl_));
		} : (std::function<void ()>)nullptr,
		[fccb = std::move(fccb)](bool hasCookie)
		{
			fccb();
		},
		true
	);
}



/* User Class */

User::User(string id) :
	id_(std::move(id)),
	conns_()
{
	enqueueForPurge(id_);
}
User::User(string id, const WebSocketConnectionPtr& conn, Room* room) :
	id_(std::move(id)),
	conns_({
		{
			room, {
				conn
			}
		}
	})
{}

UserPtr User::get(const drogon::HttpRequestPtr& req, bool extendLifespan)
{
	UserPtr user = req->attributes()->get<UserPtr>(userObjectKeyWithinFilters_);
	return std::move(user ? user : get(drogon::user::getId(req), extendLifespan));
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
