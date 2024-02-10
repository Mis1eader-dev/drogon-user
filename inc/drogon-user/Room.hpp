#pragma once

#include "drogon-user/User.hpp"
#include "drogon/HttpRequest.h"
#include "drogon/WebSocketConnection.h"
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

struct Connect
{
	UserPtr&& user;
	const drogon::WebSocketConnectionPtr conn;

	Connect(UserPtr&& user, drogon::WebSocketConnectionPtr conn) :
		user(std::move(user)),
		conn(std::move(conn))
	{}
};

struct Message
{
	std::string&& msg;
	UserPtr&& user;
	const drogon::WebSocketConnectionPtr conn;

	Message(std::string&& msg, UserPtr&& user, drogon::WebSocketConnectionPtr conn) :
		msg(std::move(msg)),
		user(std::move(user)),
		conn(std::move(conn))
	{}
};

struct Disconnect
{
	UserPtr&& user;

	Disconnect(UserPtr&& user) :
		user(std::move(user))
	{}
};

class Room
{
private:
	UserPtr add(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& conn);

	UserPtr get(std::string_view id, bool extendLifespan = true) const;
	inline UserPtr get(const drogon::HttpRequestPtr& req, bool extendLifespan = true) const
	{
		return std::move(get(drogon::user::getId(req)));
	}
	inline UserPtr get(const drogon::WebSocketConnectionPtr& conn) const
	{
		return User::get(conn);
	}

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

	

	inline void notify(const drogon::WebSocketConnectionPtr& conn, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		conn->send(msg, type);
	}
	inline void notify(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		conn->send(msg, len, type);
	}
	inline void notify(const Connect& connect, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notify(connect.conn, msg, type);
	}
	inline void notify(const Connect& connect, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notify(connect.conn, msg, len, type);
	}
	inline void notify(const Message& message, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notify(message.conn, msg, type);
	}
	inline void notify(const Message& message, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notify(message.conn, msg, len, type);
	}

	inline void notify(const UserPtr& user, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notify(user, msg.data(), msg.size(), type);
	}
	void notify(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);



	inline void notifyAll(std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAll(msg.data(), msg.size(), type);
	}
	void notifyAll(const char* msg, uint64_t len,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);



	inline void notifyAllExcept(const UserPtr& user, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(user, msg.data(), msg.size(), type);
	}
	void notifyAllExcept(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);

	inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(conn, msg.data(), msg.size(), type);
	}
	void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text);
	inline void notifyAllExcept(const Connect& connect, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(connect.conn, msg, type);
	}
	inline void notifyAllExcept(const Connect& connect, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(connect.conn, msg, len, type);
	}
	inline void notifyAllExcept(const Message& message, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(message.conn, msg, type);
	}
	inline void notifyAllExcept(const Message& message, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		notifyAllExcept(message.conn, msg, len, type);
	}

protected:
	std::unordered_map<std::string_view, UserPtr> users_;
	mutable std::shared_mutex mutex_;

	Room(std::unordered_map<std::string_view, UserPtr>&& users);
};
