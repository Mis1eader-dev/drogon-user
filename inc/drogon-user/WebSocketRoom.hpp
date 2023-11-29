#pragma once

#include "drogon-user/User.hpp"
#include "drogon/HttpTypes.h"
#include "drogon/WebSocketConnection.h"
#include "drogon/WebSocketController.h"
#include "drogon-user/Room.hpp"

struct Connect
{
	const UserPtr user;
	const drogon::WebSocketConnectionPtr conn;

	Connect(UserPtr user, drogon::WebSocketConnectionPtr conn) :
		user(std::move(user)),
		conn(std::move(conn))
	{}
};

struct Message
{
	std::string&& msg;
	const UserPtr user;
	const drogon::WebSocketConnectionPtr conn;

	Message(std::string&& msg, UserPtr user, drogon::WebSocketConnectionPtr conn) :
		msg(std::move(msg)),
		user(std::move(user)),
		conn(std::move(conn))
	{}
};

struct Disconnect
{
	const UserPtr user;

	Disconnect(UserPtr user) :
		user(std::move(user))
	{}
};

template<
	class Self,
	bool AutoCreation = true,
	bool PropagateText = true,
	bool PropagateBinary = true,
	bool PropagatePingPongs = false,
	bool DisableServerSidePing = false
>
class WebSocketRoom : public drogon::WebSocketController<Self, AutoCreation>
{
private:
	static inline Room room_;

public:

	virtual void onConnect(Connect&& connect) {}

	virtual void onMessage(Message&& message) {}

	virtual void onDisconnect(Disconnect&& disconnect) {}
	virtual void onEmpty() {}



	virtual void handleNewConnection(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& conn) final override
	{
		if constexpr(DisableServerSidePing)
			conn->disablePing();

		Connect connect(room_.add(req, conn), conn);
		onConnect(std::move(connect));
	}

	virtual void handleNewMessage(const drogon::WebSocketConnectionPtr& conn, std::string&& msg, const drogon::WebSocketMessageType& type) final override
	{
		switch(type)
		{
			case drogon::WebSocketMessageType::Text:
				if constexpr(!PropagateText)
					return;
				break;
			case drogon::WebSocketMessageType::Binary:
				if constexpr(!PropagateBinary)
					return;
				break;
			case drogon::WebSocketMessageType::Ping:
			case drogon::WebSocketMessageType::Pong:
				if constexpr(!PropagatePingPongs)
					return;
				break;
			default:
				return;
		}
		Message message(std::move(msg), room_.get(conn), conn);
		onMessage(std::move(message));
	}

	virtual void handleConnectionClosed(const drogon::WebSocketConnectionPtr& conn) final override
	{
		Disconnect disconnect(room_.remove(conn));
		onDisconnect(std::move(disconnect));
	}

	static inline void notify(const UserPtr& user, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(user, msg, type);
	}
	static inline void notify(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(user, msg, len, type);
	}

	static inline void notify(const drogon::WebSocketConnectionPtr& conn, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(conn, msg, type);
	}
	static inline void notify(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(conn, msg, len, type);
	}

	static inline void notifyAll(const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAll(msg, type);
	}
	static inline void notifyAll(const char* msg, uint64_t len,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAll(msg, len, type);
	}

	static inline void notifyAllExcept(const UserPtr& user, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(user, msg, type);
	}
	static inline void notifyAllExcept(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(user, msg, len, type);
	}

	static inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const std::string& msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(conn, msg, type);
	}
	static inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(conn, msg, len, type);
	}
};
