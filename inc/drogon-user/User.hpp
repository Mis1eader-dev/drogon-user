#pragma once

#include "drogon/Cookie.h"
#include "drogon/WebSocketConnection.h"
#include "drogon/utils/FunctionTraits.h"
#include "drogon/utils/Utilities.h"
#include <any>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

class User;
using UserPtr = std::shared_ptr<User>;

namespace drogon::user
{
	using IdGenerator = std::function<void (std::string& id)>;
	using IdEncoder = std::function<void (std::string& idUnencoded)>;

#ifdef ENABLE_OFFLINE_CALLBACK
	/// This callback is called when a user object is to be destroyed in memory,
	/// and considered offline.
	using OfflineUserCallback = std::function<void (const UserPtr& user)>;
#endif

	/// This callback is called by a [/login] endpoint to validate a client's identity.
	///
	/// The 2nd argument is any extra information needed by the callback, say User-Agent,
	/// IP address, etc. It can be ignored if not used.
	///
	/// A sample callback may look like:
	/// string_view salt;
	/// auto userData = dbQuery(identifier);
	/// if(!userData.exists())
	/// 	salt = dummySalt;
	/// else
	/// 	salt = userData.salt;
	///
	/// auto hashPass = hash(password, salt);
	/// if(hashCompare(userData.hashedPassword, hashPass) != 0)
	/// 	return {};
	///
	/// return std::move(userData);
	using DatabaseLoginValidationCallback = std::function<std::any (std::string_view identifier, std::string_view password, std::any&& extraContext)>;

	/// This callback is called when the user ID (session ID) does not exist in memory, and
	/// it validates the session ID with the database to confirm it is a valid identity.
	///
	/// The 2nd argument is any extra information needed by the callback, say User-Agent,
	/// IP address, etc. It can be ignored if not used.
	///
	/// A sample callback may look like:
	/// auto userData = dbQuery("sessions", sessionId);
	/// if(!userData.exists())
	/// 	return {};
	///
	/// return std::move(userData);
	using DatabaseSessionValidationCallback = std::function<std::any (std::string_view sessionId, std::any&& extraContext)>;

	/// This callback is called by the Logged In filters.
	using IdFormatValidator = std::function<bool (std::string_view id)>;

	/// This callback is called after the user identity is validated, either through login or
	/// session validation.
	///
	/// It can be used to perform further queries if needed, create objects, or do nothing if
	/// the objects are already in memory.
	///
	/// A sample callback may look like:
	/// auto dataCtx = std::make_shared<MyData>(std::move(data));
	/// user->setContext(dataCtx);
	///
	/// auto groupID = data.groupID;
	/// auto group = BusinessLogic::getGroup(groupID);
	/// if(group)
	/// 	return;
	///
	/// groupData = dbQuery("groups", groupID);
	/// if(!groupData.exists())
	/// 	return;
	///
	/// group = new Group(groupID, groupData.name, user, groupData.color);
	/// dataCtx->group = group;
	/// BusinessLogic::addGroup(group);
	using DatabasePostValidationCallback = std::function<void (const UserPtr& user, std::any& data)>;

	/// This callback is called just before sending login info or session ID for
	/// validation.
	///
	/// A sample callback may look like:
	/// auto agent = req->getHeader("User-Agent");
	/// auto ip = req->peerAddr().toIp();
	/// auto extraContext = std::make_pair(agent, ip);
	/// return extraContext;
	using ExtraContextGenerator = std::function<std::any (const drogon::HttpRequestPtr& req)>;

	/// This callback is called after a successful login.
	///
	/// A sample callback may look like:
	/// dbWrite("sessions", sessionId);
	using DatabaseLoginWriteCallback = std::function<void (std::string_view sessionId, std::string_view identifier, std::any&& data)>;

	/// This callback is called by a [/logout] endpoint to remove a session.
	///
	/// A sample callback may look like:
	/// dbDelete("sessions", sessionId);
	using DatabaseSessionInvalidationCallback = std::function<bool (std::string_view sessionId)>;

	/// This callback is called when a logout is initiated and the user
	/// object is alive in memory and has at least one connection.
	///
	/// A sample callback may look like:
	/// Chat::notify(user, nullptr, 0); // frontend checks if empty message received, then redirect somewhere or refresh
	using UserLogoutNotifyCallback = std::function<void (const UserPtr& user)>;

	void configure(
		std::string idCookieKey,
		std::string userObjectKeyWithinFilters,
		int idCookieMaxAge,
		drogon::Cookie::SameSite sameSite,
		bool httpOnly,
		bool secure,
		double userCacheTimeout,
		uint8_t idCookieUnencodedLen,
		uint8_t idCookieEncodedLen,
		IdGenerator&& idGenerator,
		IdEncoder&& idEncoder
	);
	inline void configure(
		std::string idCookieKey = "ID",
		std::string userObjectKeyWithinFilters = "",
		int idCookieMaxAge = 86400,
		drogon::Cookie::SameSite sameSite = drogon::Cookie::SameSite::kStrict,
		bool httpOnly = true,
		bool secure = true,
		double userCacheTimeout = 20.0)
	{
		configure(std::move(idCookieKey), std::move(userObjectKeyWithinFilters), idCookieMaxAge, sameSite, httpOnly, secure, userCacheTimeout, 0, 0, nullptr, nullptr);
	}
	inline void configure(
		std::string idCookieKey,
		std::string userObjectKeyWithinFilters,
		int idCookieMaxAge,
		drogon::Cookie::SameSite sameSite,
		bool httpOnly,
		bool secure,
		double userCacheTimeout,
		uint8_t idCookieUnencodedLen,
		IdGenerator&& idGenerator)
	{
		configure(std::move(idCookieKey), std::move(userObjectKeyWithinFilters), idCookieMaxAge, sameSite, httpOnly, secure, userCacheTimeout, idCookieUnencodedLen, 0, std::move(idGenerator), nullptr);
	}
	inline void configure(
		std::string idCookieKey,
		std::string userObjectKeyWithinFilters,
		int idCookieMaxAge,
		drogon::Cookie::SameSite sameSite,
		bool httpOnly,
		bool secure,
		double userCacheTimeout,
		uint8_t idCookieUnencodedLen,
		uint8_t idCookieEncodedLen,
		IdGenerator&& idGenerator)
	{
		configure(std::move(idCookieKey), std::move(userObjectKeyWithinFilters), idCookieMaxAge, sameSite, httpOnly, secure, userCacheTimeout, idCookieUnencodedLen, idCookieEncodedLen, std::move(idGenerator), nullptr);
	}
	inline void configure(
		std::string idCookieKey,
		std::string userObjectKeyWithinFilters,
		int idCookieMaxAge,
		drogon::Cookie::SameSite sameSite,
		bool httpOnly,
		bool secure,
		double userCacheTimeout,
		uint8_t idCookieUnencodedLen,
		IdGenerator&& idGenerator,
		IdEncoder&& idEncoder)
	{
		configure(std::move(idCookieKey), std::move(userObjectKeyWithinFilters), idCookieMaxAge, sameSite, httpOnly, secure, userCacheTimeout, idCookieUnencodedLen, 0, std::move(idGenerator), std::move(idEncoder));
	}

	void configureDatabase(
		DatabaseLoginValidationCallback&& loginValidationCallback,
		DatabaseSessionValidationCallback&& sessionValidationCallback,
		DatabaseLoginWriteCallback&& loginWriteCallback,

		DatabaseSessionInvalidationCallback&& sessionInvalidationCallback,

		/// Optional
		UserLogoutNotifyCallback userLogoutNotifyCallback = nullptr,

		/// Can be set to `nullptr` if no validation is desired.
		///
		/// NOTE: Even if set to `nullptr`, the length is still checked.
		IdFormatValidator idValidator = drogon::utils::isBase64,

		/// Optional
		ExtraContextGenerator extraContextGenerator = nullptr,

		/// Optional
		DatabasePostValidationCallback postValidationCallback = nullptr,

		uint8_t minimumIdentifierLength = 3,
		uint8_t maximumIdentifierLength = 254,
		uint8_t minimumPasswordLength = 8,
		uint8_t maximumPasswordLength = 128,
		const std::string& loginEndpoint = "/api/login",
		const std::string& logoutEndpoint = "/api/logout",

		/// Set to empty to disable redirect from unauthorized pages
		///
		/// Active on handlers with the filter "drogon::user::filter::page::UnloggedIn"
		std::string unloggedInRedirectTo = "/login",

		/// Set to empty to disable redirect from login page when already logged in
		///
		/// Active on handlers with the filter "drogon::user::filter::page::LoggedIn"
		std::string loggedInRedirectTo = "/admin"
	);

#ifdef ENABLE_OFFLINE_CALLBACK
	void registerOfflineUserCallback(OfflineUserCallback&& cb);
#endif

	std::string generateId();
	void generateIdFor(const drogon::HttpResponsePtr& resp, std::string id);
	inline void generateIdFor(const drogon::HttpResponsePtr& resp)
	{
		generateIdFor(resp, std::move(generateId()));
	}

	void removeIdFor(const drogon::HttpResponsePtr& resp);

	const std::string& getIdRef(const drogon::HttpRequestPtr& req);
	inline std::string_view getId(const drogon::HttpRequestPtr& req)
	{
		return getIdRef(req);
	}

	inline void prolongIdFor(const drogon::HttpResponsePtr& resp, const std::string& id)
	{
		generateIdFor(resp, id);
	}
	inline void prolongIdFor(const drogon::HttpRequestPtr& req, const drogon::HttpResponsePtr& resp)
	{
		prolongIdFor(resp, getIdRef(req));
	}

	/// This function can be called by a filter to customize the behavior of session validation
	///
	/// `positiveCallback` will be called if the session validation is successful
	/// `negativeCallback` will be called otherwise
	///
	/// Only one of the two functions can be `nullptr`, in which case only one
	/// of the callbacks will be called in either case
	void loggedInFilter(
		const drogon::HttpRequestPtr& req,
		std::function<void ()>&& positiveCallback,
		std::function<void (bool hasCookie)>&& negativeCallback,
		bool checkIndexHtmlOnly = false
	);
}

class Room;

#ifdef ENABLE_GROUPS
class Group;
using GroupPtr = std::shared_ptr<Group>;
#endif

class User
{
private:
	const std::string id_;
	std::shared_ptr<void> contextPtr_;

	using ConnsSet = std::unordered_set<drogon::WebSocketConnectionPtr>;
	std::unordered_map<Room*, ConnsSet> conns_;
	mutable std::shared_mutex mutex_;

	mutable std::atomic_size_t manualClosures_ = 0;
	mutable std::condition_variable manualClosuresCv_;
	mutable std::mutex manualClosuresMutex_;

	mutable std::condition_variable initCv_;
	mutable std::mutex initMutex_;

	friend class Room;

#ifdef ENABLE_GROUPS
	std::unordered_map<std::string_view, GroupPtr> groups_;
	mutable std::shared_mutex groupsMutex_;

	friend class Group;
#endif

	static UserPtr create(std::string_view id, const drogon::WebSocketConnectionPtr& conn, Room* room);

	static void enqueueForPurge(std::string_view id);

	/// Extends the purge if it has already been enqueued for purging
	///
	/// NOTE: The id must come from the user object itself
	static void prolongPurge(std::string_view id);

	/// Extends the purge if any one of them have already been enqueued for purging
	///
	/// NOTE: The id must come from the user object itself
	static void prolongPurges(const std::vector<std::string_view>& ids);

public:
	User(std::string id);
	User(std::string id, const drogon::WebSocketConnectionPtr& conn, Room* room);

	User(const User&) = delete;
	User& operator = (const User&) = delete;

	/// This must only be called if the user is not in memory,
	/// and user's presence in memory is needed in that instant.
	static UserPtr create(std::string_view id);

	static UserPtr get(std::string_view id, bool extendLifespan = false);
	/// If one of the 4 provided filters has been hit before calling this method,
	/// then the User object within the request will be returned.
	///
	/// Otherwise it will be a global lookup of the user.
	static UserPtr get(const drogon::HttpRequestPtr& req, bool extendLifespan = false);
	static inline UserPtr get(const drogon::WebSocketConnectionPtr& conn)
	{
		return conn->getContext<User>();
	}

	inline std::string_view id() const
	{
		return id_;
	}

	/// Closes connections from all rooms
	void forceClose();

	/**
	 * @brief Set custom data on the connection
	 *
	 * @param context The custom data.
	 */
	void setContext(const std::shared_ptr<void>& context);

	/**
	 * @brief Set custom data on the connection
	 *
	 * @param context The custom data.
	 */
	void setContext(std::shared_ptr<void>&& context);

	/**
	 * @brief Get custom data from the connection
	 *
	 * @tparam T The type of the data
	 * @return std::shared_ptr<T> The smart pointer to the data object.
	 */
	template<typename T>
	std::shared_ptr<T> getContext() const
	{
		std::unique_lock lock(initMutex_);
		initCv_.wait(lock, [this]() -> bool
		{
			return hasContext();
		});
		return std::static_pointer_cast<T>(contextPtr_);
	}

	/**
	 * @brief Get the custom data reference from the connection.
	 * @note Please make sure that the context is available.
	 * @tparam T The type of the data stored in the context.
	 * @return T&
	 */
	template<typename T>
	T& getContextRef() const
	{
		std::unique_lock lock(initMutex_);
		initCv_.wait(lock, [this]() -> bool
		{
			return hasContext();
		});
		return *(static_cast<T *>(contextPtr_.get()));
	}

	/// Return true if the context is set by user.
	bool hasContext() const;

	/// Clear the context.
	void clearContext();



#ifdef ENABLE_GROUPS
	/// If `sizePredicate` is 0, then if not empty, it returns the first group (from groups.begin()).
	///
	/// Else, it returns groups.begin() only when the size of groups is exactly the predicate.
	GroupPtr firstGroup(size_t sizePredicate = 0) const;

	std::vector<GroupPtr> groups() const;
#endif
};
