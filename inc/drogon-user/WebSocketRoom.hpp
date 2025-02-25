#pragma once

#include "drogon/HttpTypes.h"
#include "drogon/WebSocketConnection.h"
#include "drogon/WebSocketController.h"
#include "drogon-user/Room.hpp"
// #include "Room.hpp"
#include "drogon-user/User.hpp"
// #include "User.hpp"
#include <json/value.h>
#include <string>
#include <string_view>

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

	// virtual void onEmpty() {}



	virtual void handleNewConnection(const drogon::HttpRequestPtr& req, const drogon::WebSocketConnectionPtr& conn) final override
	{
		if constexpr(DisableServerSidePing)
			conn->disablePing();

		Connect connect(std::move(room_.add(req, conn)), conn);
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

		UserPtr user = room_.get(conn);
		if(!user)
			return;

		Message message(std::move(user), conn, std::move(msg));
		onMessage(std::move(message));
	}

	virtual void handleConnectionClosed(const drogon::WebSocketConnectionPtr& conn) final override
	{
		UserPtr user = room_.remove(conn);
		if(!user)
			return;

		Disconnect disconnect(std::move(user), conn);
		onDisconnect(std::move(disconnect));
	}



	static inline void notify(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(conn, msg, len, type);
	}
	static inline void notify(const drogon::WebSocketConnectionPtr& conn, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(conn, msg, type);
	}
	static inline void notify(const drogon::WebSocketConnectionPtr& conn, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(conn, json, type);
	}
	static inline void notify(const drogon::WebSocketConnectionPtr& conn, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(conn, json, type);
	}
	static inline void notify(const Connect& connect, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(connect, msg, len, type);
	}
	static inline void notify(const Connect& connect, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(connect, msg, type);
	}
	static inline void notify(const Connect& connect, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(connect, json, type);
	}
	static inline void notify(const Connect& connect, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(connect, json, type);
	}
	static inline void notify(const Message& message, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(message, msg, len, type);
	}
	static inline void notify(const Message& message, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(message, msg, type);
	}
	static inline void notify(const Message& message, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(message, json, type);
	}
	static inline void notify(const Message& message, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(message, json, type);
	}

	static inline void notify(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(user, msg, len, type);
	}
	static inline void notify(const UserPtr& user, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(user, msg, type);
	}
	static inline void notify(const UserPtr& user, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(user, json, type);
	}
	static inline void notify(const UserPtr& user, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notify(user, json, type);
	}



	static inline void notifyAll(const char* msg, uint64_t len,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAll(msg, len, type);
	}
	static inline void notifyAll(std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAll(msg, type);
	}
	static inline void notifyAll(Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAll(json, type);
	}
	static inline void notifyAll(const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAll(json, type);
	}



	static inline void notifyAllExcept(const UserPtr& user, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(user, msg, len, type);
	}
	static inline void notifyAllExcept(const UserPtr& user, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(user, msg, type);
	}
	static inline void notifyAllExcept(const UserPtr& user, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(user, json, type);
	}
	static inline void notifyAllExcept(const UserPtr& user, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(user, json, type);
	}

	static inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(conn, msg, len, type);
	}
	static inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(conn, msg, type);
	}
	static inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(conn, json, type);
	}
	static inline void notifyAllExcept(const drogon::WebSocketConnectionPtr& conn, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(conn, json, type);
	}
	static inline void notifyAllExcept(const Connect& connect, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(connect, msg, len, type);
	}
	static inline void notifyAllExcept(const Connect& connect, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(connect, msg, type);
	}
	static inline void notifyAllExcept(const Connect& connect, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(connect, json, type);
	}
	static inline void notifyAllExcept(const Connect& connect, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(connect, json, type);
	}
	static inline void notifyAllExcept(const Message& message, const char* msg,
		uint64_t len, const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(message, msg, len, type);
	}
	static inline void notifyAllExcept(const Message& message, std::string_view msg,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(message, msg, type);
	}
	static inline void notifyAllExcept(const Message& message, Json::Value& json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(message, json, type);
	}
	static inline void notifyAllExcept(const Message& message, const Json::Value* json,
		const drogon::WebSocketMessageType type = drogon::WebSocketMessageType::Text)
	{
		room_.notifyAllExcept(message, json, type);
	}



	static inline Room& room()
	{
		return room_;
	}
	static inline Room* roomPtr()
	{
		return &room_;
	}
};
