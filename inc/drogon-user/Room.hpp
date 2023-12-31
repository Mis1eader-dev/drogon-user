#pragma once

#include "drogon-user/User.hpp"
#include "drogon/HttpRequest.h"
#include "drogon/WebSocketConnection.h"
#include <shared_mutex>
#include <string_view>
#include <unordered_map>

class Room
{
private:
	UserPtr add(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& conn);

	UserPtr get(std::string_view id) const;
	UserPtr get(const drogon::HttpRequestPtr& req) const;
	UserPtr get(const drogon::WebSocketConnectionPtr& conn) const;

	UserPtr remove(const UserPtr& user);
	UserPtr remove(const drogon::WebSocketConnectionPtr& conn);

	template<
		class Self,
		bool AutoCreation,
		bool PropagateText,
		bool PropagateBinary,
		bool PropagatePingPongs,
		bool DisableServerSidePing
	>
	friend class WebSocketRoom;
	friend class User;
#ifdef ENABLE_GROUPS
	friend class Group;
#endif

public:
	Room();

	inline void notify(const drogon::WebSocketConnectionPtr& conn, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		conn->send(msg, type);
	}
	inline void notify(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		conn->send(msg, len, type);
	}

	inline void notify(const UserPtr& user, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notify(user, msg.data(), msg.size(), type);
	}
	void notify(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);



	inline void notifyAll(const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAll(msg.data(), msg.size(), type);
	}
	void notifyAll(const char* msg, uint64_t len,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);



	inline void notifyAllExcept(const UserPtr& user, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(user, msg.data(), msg.size(), type);
	}
	void notifyAllExcept(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);

	inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(conn, msg.data(), msg.size(), type);
	}
	void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);

protected:
	std::unordered_map<std::string_view, UserPtr> users_;
	mutable std::shared_mutex mutex_;

	Room(std::unordered_map<std::string_view, UserPtr>&& users);
};
