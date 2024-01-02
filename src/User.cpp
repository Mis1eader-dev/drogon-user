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

static string idCookieKey_;
static uint8_t idUnencodedLen_, idLen_;
static int maxAge_;
static constexpr Cookie::SameSite sameSite_ = Cookie::SameSite::kStrict;
static user::IdGenerator idGenerator_;
static user::IdEncoder idEncoder_;
static user::DatabaseSessionValidationCallback sessionValidationCallback_;
static user::DatabaseLoginWriteCallback loginWriteCallback_;
static user::IdValidator idValidator_;
static user::DatabasePostValidationCallback postValidationCallback_;
static user::ExtraContextGenerator extraContextGenerator_;
static bool hasLoginRedirect_ = false, hasLoggedInRedirect_ = false;
static string loginPageUrl_, loggedInPageUrl_;

static trantor::ConcurrentTaskQueue taskQueue_(std::thread::hardware_concurrency(), "");

void user::configure(
	string_view idCookieKey,
	int maxAge,
	double userCacheTimeout)
{
	configure(idCookieKey, maxAge, userCacheTimeout, 0, 0, nullptr, nullptr);
}
void user::configure(
	string_view idCookieKey,
	int maxAge,
	double userCacheTimeout,
	uint8_t idUnencodedLen,
	IdGenerator&& idGenerator)
{
	configure(idCookieKey, maxAge, userCacheTimeout, idUnencodedLen, 0, std::move(idGenerator), nullptr);
}
void user::configure(
	string_view idCookieKey,
	int maxAge,
	double userCacheTimeout,
	uint8_t idUnencodedLen,
	uint8_t idEncodedLen,
	IdGenerator&& idGenerator)
{
	configure(idCookieKey, maxAge, userCacheTimeout, idUnencodedLen, idEncodedLen, std::move(idGenerator), nullptr);
}
void user::configure(
	string_view idCookieKey,
	int maxAge,
	double userCacheTimeout,
	uint8_t idUnencodedLen,
	IdGenerator&& idGenerator,
	IdEncoder&& idEncoder)
{
	configure(idCookieKey, maxAge, userCacheTimeout, idUnencodedLen, 0, std::move(idGenerator), std::move(idEncoder));
}
void user::configure(
	string_view idCookieKey,
	int maxAge,
	double userCacheTimeout,
	uint8_t idUnencodedLen,
	uint8_t idEncodedLen,
	IdGenerator&& idGenerator,
	IdEncoder&& idEncoder)
{
	idCookieKey_ = idCookieKey;
	idUnencodedLen_ = idUnencodedLen ? idUnencodedLen : 16;
	idLen_ = idEncodedLen ? idEncodedLen : utils::base64EncodedLength(idUnencodedLen_, false);
	maxAge_ = maxAge;
	userCacheTimeout_ = userCacheTimeout;
	idGenerator_ = std::move(
		idGenerator ? idGenerator : [](string& id) -> void
		{
			drogon::utils::secureRandomBytes(id.data(), idUnencodedLen_);
		}
	);
	idEncoder_ = std::move(
		idEncoder ? idEncoder : [](string& idUnencoded) -> void
		{
			idUnencoded = utils::base64Encode(idUnencoded, true, false);
		}
	);
}
void user::configureDatabase(
	DatabaseLoginValidationCallback&& loginValidationCallback,
	DatabaseSessionValidationCallback&& sessionValidationCallback,
	DatabaseLoginWriteCallback&& loginWriteCallback,
	DatabaseSessionInvalidationCallback&& sessionInvalidationCallback,
	UserLogoutNotifyCallback userLogoutNotifyCallback,
	IdValidator idValidator,
	ExtraContextGenerator extraContextGenerator,
	DatabasePostValidationCallback postValidationCallback,
	const string& identifierHeaderName,
	uint8_t minimumIdentifierLength,
	uint8_t maximumIdentifierLength,
	const string& passwordHeaderName,
	uint8_t minimumPasswordLength,
	uint8_t maximumPasswordLength,
	const string& loginValidationEndpoint,
	const string& logoutValidationEndpoint,
	const string& loginPageUrl,
	const string& loggedInPageUrl)
{
	sessionValidationCallback_ = std::move(sessionValidationCallback);
	loginWriteCallback_ = std::move(loginWriteCallback);
	idValidator_ = idValidator;
	extraContextGenerator_ = extraContextGenerator;
	postValidationCallback_ = postValidationCallback;
	loginPageUrl_ = std::move(loginPageUrl);
	loggedInPageUrl_ = std::move(loggedInPageUrl);
	hasLoginRedirect_ = !loginPageUrl_.empty();
	hasLoggedInRedirect_ = !loggedInPageUrl_.empty();

	// Login endpoint
	app().registerHandler(loginValidationEndpoint,
		[
			identifierHeaderName = std::move(identifierHeaderName),
			minimumIdentifierLength,
			maximumIdentifierLength,
			passwordHeaderName = std::move(passwordHeaderName),
			minimumPasswordLength,
			maximumPasswordLength,
			loginValidationCallback = std::move(loginValidationCallback)
		]
		(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr&)>&& callback) -> void
	{
		const string_view identifier = req->getHeader(identifierHeaderName);
		auto len = identifier.size();
		if(len < minimumIdentifierLength || len > maximumIdentifierLength)
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		const string_view password =
			string_view(req->getHeader(passwordHeaderName))
				.substr(0, maximumPasswordLength);
		len = password.size();
		if(len < minimumPasswordLength)
		{
			callback(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
			return;
		}

		// ^ Length: OK

		std::any extraContext;
		if(extraContextGenerator_)
			extraContext = extraContextGenerator_(req);

		taskQueue_.runTaskInQueue(
		[
			req = std::move(req),
			identifier,
			password,
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

			string sessionId;
			generateId(sessionId);

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

			loginWriteCallback_(sessionId, identifier, data);

			// ^ Database: OK
		});
	},
	{
		HttpMethod::Post
	});

	// Logout endpoint
	app().registerHandler(logoutValidationEndpoint,
		[
			sessionInvalidationCallback = std::move(sessionInvalidationCallback),
			userLogoutNotifyCallback = std::move(userLogoutNotifyCallback)
		](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr&)>&& callback) -> void
	{
		auto id = user::getId(req);
		if(UserPtr user = User::get(id))
		{
			if(userLogoutNotifyCallback)
				userLogoutNotifyCallback(user);

			user->forceClose();
		}

		taskQueue_.runTaskInQueue(
		[
			req = std::move(req),
			callback = std::move(callback),
			id = std::move(id),
			sessionInvalidationCallback = std::move(sessionInvalidationCallback)
		]()
		{
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
		});
	},
	{
		HttpMethod::Delete
	});
}

#ifdef ENABLE_OFFLINE_CALLBACK
void user::registerOfflineUserCallback(OfflineUserCallback cb)
{
	offlineUserCallbacks_.push_back(std::move(cb));
}
#endif

string user::generateId()
{
	string id;
	generateId(id);
	return id;
}
void user::generateId(string& id)
{
	id.reserve(idLen_);
	id.resize(idUnencodedLen_);
	idGenerator_(id);
	idEncoder_(id);
}

void user::generateIdFor(const HttpResponsePtr& resp)
{
	string id;
	generateId(id);
	generateIdFor(resp, std::move(id));
}

void user::generateIdFor(const HttpResponsePtr& resp, const string& id)
{
	Cookie cookie(idCookieKey_, id);
	cookie.setPath("/");
	cookie.setMaxAge(maxAge_);
	cookie.setSameSite(sameSite_);
	cookie.setHttpOnly(true);
	resp->addCookie(std::move(cookie));
}

void user::removeIdFor(const HttpResponsePtr& resp)
{
	Cookie cookie(idCookieKey_, "");
	cookie.setPath("/");
	cookie.setMaxAge(0);
	cookie.setSameSite(sameSite_);
	cookie.setHttpOnly(true);
	resp->addCookie(std::move(cookie));
}

string_view user::getId(const HttpRequestPtr& req)
{
	return req->getCookie(idCookieKey_);
}



/* Security */

namespace drogon::user
{
	class LoggedInAPI : public HttpFilter<LoggedInAPI>
	{
	public:
		void doFilter(const HttpRequestPtr& req,
						FilterCallback&& fcb,
						FilterChainCallback&& fccb) override;
	};

	class LoggedInPage : public HttpFilter<LoggedInPage>
	{
	public:
		void doFilter(const HttpRequestPtr& req,
						FilterCallback&& fcb,
						FilterChainCallback&& fccb) override;
	};

	class UnloggedInPage : public HttpFilter<UnloggedInPage>
	{
	public:
		void doFilter(const HttpRequestPtr& req,
						FilterCallback&& fcb,
						FilterChainCallback&& fccb) override;
	};
}

static void loginFilter(const HttpRequestPtr& req, std::function<void ()>&& positiveCallback, std::function<void ()>&& negativeCallback, bool checkIndexHtmlOnly = false)
{
	/*if(checkIndexHtmlOnly) // TODO:
	{
		string_view path = req->path();
		if()
		positiveCallback();
		return;
	}*/

	auto id = user::getId(req);
	if(id.size() != idLen_ ||
		idValidator_ && !idValidator_(id))
	{
		if(negativeCallback)
			negativeCallback();
		else
			positiveCallback();
		return;
	}

	if(User::get(id)) // Is in a room and logged in
	{
		if(positiveCallback)
			positiveCallback();
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
			negativeCallback = std::move(negativeCallback)
		]()
	{
		auto data = sessionValidationCallback_(id, extraContext);
		if(!data.has_value()) // Incorrect credentials
		{
			if(negativeCallback)
				negativeCallback();
			else
				positiveCallback();
			return;
		}

		// Successful session validation

		UserPtr user = std::move(User::create(id));
		if(postValidationCallback_)
			postValidationCallback_(std::move(user), std::move(data));

		if(positiveCallback)
			positiveCallback();
		else
			negativeCallback();
	});
}

void drogon::user::LoggedInAPI::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loginFilter(req, [fccb = std::move(fccb)]()
	{
		fccb();
	}, [fcb = std::move(fcb)]()
	{
		fcb(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
	});
}

void drogon::user::LoggedInPage::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loginFilter(
		req,
		[fccb = std::move(fccb)]()
		{
			fccb();
		}, hasLoginRedirect_ ? [fcb = std::move(fcb)]()
		{
			fcb(HttpResponse::newRedirectionResponse(loginPageUrl_));
		} : (std::function<void ()>)nullptr,
		true
	);
}

void drogon::user::UnloggedInPage::doFilter(const HttpRequestPtr& req, FilterCallback&& fcb, FilterChainCallback&& fccb)
{
	loginFilter(
		req,
		hasLoggedInRedirect_ ? [fcb = std::move(fcb)]()
		{
			fcb(HttpResponse::newRedirectionResponse(loggedInPageUrl_));
		} : (std::function<void ()>)nullptr,
		[fccb = std::move(fccb)]()
		{
			fccb();
		},
		true
	);
}



/* User Class */

User::User(const string& id) :
	id_(id),
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

string_view User::id() const
{
	return id_;
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
