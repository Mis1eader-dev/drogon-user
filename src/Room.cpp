#include "drogon-user/Room.hpp"
#include "drogon-user/User.hpp"
#include "drogon/HttpAppFramework.h"
#include "drogon/WebSocketConnection.h"
#include "trantor/net/EventLoop.h"
#include <json/value.h>
#include <json/writer.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <utility>

#ifdef ENABLE_OFFLINE_CALLBACK
#include <vector>
#endif

using namespace drogon;
using std::string;
using std::string_view;
using std::scoped_lock;
using std::shared_lock;

static std::shared_mutex mutex_;
static std::unordered_map<string_view, UserPtr> allUsers_;

static std::mutex timeoutsMutex_;
static std::unordered_map<string_view, trantor::TimerId> timeouts_;

namespace drogon::user
{
	double userCacheTimeout_;

#ifdef ENABLE_OFFLINE_CALLBACK
	std::vector<OfflineUserCallback> offlineUserCallbacks_;
#endif
}

Room::Room() :
	users_()
{}

Room::Room(std::unordered_map<std::string_view, UserPtr>&& users) :
	users_(std::move(users))
{}

static inline trantor::TimerId enqueuePurge(string_view id)
{
	return drogon::app().getLoop()->runAfter(
		user::userCacheTimeout_,
		[id]()
		{
		#ifdef ENABLE_OFFLINE_CALLBACK
			UserPtr user = nullptr;
			{
				scoped_lock lock(::mutex_);
				auto find = ::allUsers_.find(id);
				if(find != ::allUsers_.end())
				{
					user = find->second;
					::allUsers_.erase(find);
				}
			}
		#endif

			{
				scoped_lock lock(::timeoutsMutex_);
				::timeouts_.erase(id);
			}

		#ifdef ENABLE_OFFLINE_CALLBACK
			if(!user)
				return;

			for(const auto& cb : user::offlineUserCallbacks_)
				cb(user);
		#else
			// Must happen after the timeout removal
			scoped_lock lock(::mutex_);
			::allUsers_.erase(id);
		#endif
		}
	);
}

UserPtr User::create(string_view id)
{
	UserPtr user = std::make_shared<User>(id);
	id = user->id_;
	{
		scoped_lock lock(::mutex_);
		::allUsers_.emplace(id, user);
	}
	{
		scoped_lock lock(::timeoutsMutex_);
		::timeouts_.emplace(id, ::enqueuePurge(id));
	}
	return user;
}
UserPtr User::create(string_view id, const WebSocketConnectionPtr& conn, Room* room)
{
	UserPtr user = std::make_shared<User>(id, conn, room);
	id = user->id_;
	{
		scoped_lock lock(room->mutex_);
		room->users_.emplace(id, user);
	}
	{
		scoped_lock lock(::mutex_);
		::allUsers_.emplace(id, user);
	}
	return user;
}

void User::prolongPurge(string_view id)
{
	scoped_lock lock(::timeoutsMutex_);
	auto find = ::timeouts_.find(id);
	if(find == ::timeouts_.end())
		return;

	drogon::app().getLoop()->invalidateTimer(find->second);
	find->second = ::enqueuePurge(id);
}

void User::prolongPurges(const std::vector<string_view>& ids)
{
	auto loop = drogon::app().getLoop();

	scoped_lock lock(::timeoutsMutex_);
	auto end = ::timeouts_.end();
	for(string_view id : ids)
	{
		auto find = ::timeouts_.find(id);
		if(find == end)
			continue;

		loop->invalidateTimer(find->second);
		find->second = ::enqueuePurge(id);
	}
}

void User::forceClose()
{
	{
		scoped_lock lock(::timeoutsMutex_);
		auto find = ::timeouts_.find(id_);
		if(find != ::timeouts_.end())
		{
			drogon::app().getLoop()->invalidateTimer(find->second);
			::timeouts_.erase(find);
		}
	}

#ifdef ENABLE_OFFLINE_CALLBACK
	UserPtr user = nullptr;
	{
		scoped_lock lock(::mutex_);
		auto find = ::allUsers_.find(id_);
		if(find != ::allUsers_.end())
		{
			user = find->second;
			::allUsers_.erase(find);
		}
	}
#endif

	std::vector<Room*> rooms;
	{
		scoped_lock lock(mutex_);
		rooms.reserve(conns_.size());
		for(const auto& [room, conns] : conns_)
		{
			manualClosures_ += conns.size();
			rooms.emplace_back(room);
		}

		for(const auto& [_, conns] : conns_)
			for(const WebSocketConnectionPtr& conn : conns)
				conn->forceClose();

		conns_.clear();

	}

	{ // wait until all disconnect callbacks have finished
		std::unique_lock lock(manualClosuresMutex_);
		manualClosuresCv_.wait(lock, [this]() -> bool
		{
			return manualClosures_ == 0;
		});
	}

	for(const auto& room : rooms)
	{
		scoped_lock lock(room->mutex_);
		room->users_.erase(id_);
	}

#ifdef ENABLE_OFFLINE_CALLBACK
	if(!user)
		return;

	for(const auto& cb : user::offlineUserCallbacks_)
		cb(user);
#else
	// Must happen after the timeout removal
	scoped_lock lock(::mutex_);
	::allUsers_.erase(id_);
#endif
}

void User::forceClose(Room* room)
{
	{
		scoped_lock lock(mutex_);
		auto find = conns_.find(room);
		if(find == conns_.end())
			return;

		const auto& conns = find->second;
		manualClosures_ += conns.size();
		for(const WebSocketConnectionPtr& conn : conns)
			conn->forceClose();

		conns_.erase(find);

	}

	{ // wait until all disconnect callbacks have finished
		std::unique_lock lock(manualClosuresMutex_);
		manualClosuresCv_.wait(lock, [this]() -> bool
		{
			return manualClosures_ == 0;
		});
	}

	scoped_lock lock(room->mutex_);
	room->users_.erase(id_);
}

UserPtr User::get(string_view id, bool extendLifespan)
{
	UserPtr user = nullptr;
	{
		shared_lock slock(::mutex_);
		auto find = ::allUsers_.find(id);
		if(find == ::allUsers_.end())
			return user;

		user = find->second;
	}

	if(extendLifespan)
		User::prolongPurge(user->id_);

	return user;
}

UserPtr Room::add(const HttpRequestPtr& req, const WebSocketConnectionPtr& conn)
{
	string_view id = user::getId(req);
	UserPtr user = get(id);
	if(user) // Available in current room
	{
		scoped_lock lock(user->mutex_);
		user->conns_[this].insert(conn);
		conn->setContext(
			std::make_shared<User::WebSocketConnectionContext>(
				user
			)
		);
		return user;
	}

	user = User::get(id);
	if(!user) // Unavailable anywhere
	{
		user = User::create(id, conn, this);
		conn->setContext(
			std::make_shared<User::WebSocketConnectionContext>(
				user
			)
		);
		return user;
	}

	// Available in memory
	conn->setContext(
		std::make_shared<User::WebSocketConnectionContext>(
			user
		)
	);

	id = user->id_; // Pointer copy

	{
		scoped_lock lock(::timeoutsMutex_);
		auto find = ::timeouts_.find(id);
		if(find != ::timeouts_.end())
		{
			drogon::app().getLoop()->invalidateTimer(find->second);
			::timeouts_.erase(find);
		}
	}

	{
		scoped_lock lock(user->mutex_);
		user->conns_.emplace(
			this,
			User::ConnsSet
			{
				conn
			}
		);
	}

	{
		scoped_lock lock(mutex_);
		users_.emplace(id, user);
	}

	return user;
}

UserPtr Room::get(std::string_view id, bool extendLifespan) const
{
	UserPtr user = nullptr;
	{
		shared_lock slock(mutex_);
		auto find = users_.find(id);
		if(find == users_.end())
			return user;

		user = find->second;
	}

	if(extendLifespan)
		User::prolongPurge(user->id_);

	return user;
}

UserPtr Room::remove(const UserPtr& user)
{
	{
		scoped_lock lock(user->mutex_);
		user->conns_.erase(this);
	}
	{
		scoped_lock lock(mutex_);
		users_.erase(user->id_);
	}
	return user;
}
UserPtr Room::remove(const WebSocketConnectionPtr& conn)
{
	UserPtr user = get(conn);
	if(!user)
		return nullptr;

	if(user->manualClosures_ > 0)
	{
		if(--(user->manualClosures_) == 0)
			user->manualClosuresCv_.notify_all();
		return nullptr;
	}

	auto& connsMap = user->conns_;

	string_view id;
	bool enqueueForPurge = false;
	{
		scoped_lock lock(user->mutex_);
		auto find = connsMap.find(this);
		if(find == connsMap.end())
			return user;

		auto& connsSet = find->second;
		if(connsSet.size() == 1) // Final connection to room
		{
			id = user->id_;
			if(connsMap.size() == 1) // Final connection to server
			{
				connsMap.clear();
				enqueueForPurge = true;
			}
			else
				connsMap.erase(this);
		}
		else
			connsSet.erase(conn);
	}

	if(enqueueForPurge)
	{
		std::scoped_lock lock(::timeoutsMutex_);
		::timeouts_.emplace(id, ::enqueuePurge(id));
	}

	if(!id.empty())
	{
		scoped_lock lock(mutex_);
		users_.erase(id);
	}

	return user;
}

void Room::notify(const WebSocketConnectionPtr& conn, Json::Value& json,
	const WebSocketMessageType type)
{
	Json::FastWriter writer;
	writer.omitEndingLineFeed();
	auto msg = writer.write(json);
	notify(conn, msg.data(), msg.size(), type);
}

void Room::notify(const UserPtr& user, const char* msg,
	uint64_t len, const WebSocketMessageType type)
{
	const auto& connsMap = user->conns_;
	shared_lock slock(user->mutex_);
	const auto find = connsMap.find(this);
	if(find == connsMap.end())
		return;

	for(const WebSocketConnectionPtr& conn : find->second)
		notify(conn, msg, len, type);
}
void Room::notify(const UserPtr& user, Json::Value& json,
	const WebSocketMessageType type)
{
	Json::FastWriter writer;
	writer.omitEndingLineFeed();
	auto msg = writer.write(json);
	notify(user, msg.data(), msg.size(), type);
}

void Room::notifyAll(const char* msg, uint64_t len,
	const WebSocketMessageType type)
{
	shared_lock slock(mutex_);
	for(const auto& [_, user] : users_)
		notify(user, msg, len, type);
}
void Room::notifyAll(Json::Value& json,
	const WebSocketMessageType type)
{
	Json::FastWriter writer;
	writer.omitEndingLineFeed();
	auto msg = writer.write(json);
	notifyAll(msg.data(), msg.size(), type);
}

void Room::notifyAllExcept(const UserPtr& user, const char* msg,
	uint64_t len, const WebSocketMessageType type)
{
	shared_lock slock(mutex_);
	auto it = users_.cbegin();
	const auto end = users_.cend();
	for(; it != end; ++it)
	{
		const UserPtr& cur = it->second;
		if(cur == user)
		{
			++it;
			break;
		}
		notify(user, msg, len, type);
	}
	for(; it != end; ++it)
		notify(it->second, msg, len, type);
}
void Room::notifyAllExcept(const UserPtr& user, Json::Value& json,
	const WebSocketMessageType type)
{
	Json::FastWriter writer;
	writer.omitEndingLineFeed();
	auto msg = writer.write(json);
	notifyAllExcept(user, msg.data(), msg.size(), type);
}

void Room::notifyAllExcept(const WebSocketConnectionPtr& conn, const char* msg,
	uint64_t len, const WebSocketMessageType type)
{
	const UserPtr user = get(conn);
	notifyAllExcept(user, msg, len, type);

	const auto& connsMap = user->conns_;
	shared_lock slock(user->mutex_);
	const auto find = connsMap.find(this);
	if(find == connsMap.end())
		return;

	const auto& connsSet = find->second;
	auto it = connsSet.cbegin();
	const auto end = connsSet.cend();
	for(; it != end; ++it)
	{
		const WebSocketConnectionPtr& cur = *it;
		if(cur == conn)
		{
			++it;
			break;
		}
		notify(cur, msg, len, type);
	}
	for(; it != end; ++it)
		notify(*it, msg, len, type);
}
void Room::notifyAllExcept(const WebSocketConnectionPtr& conn, Json::Value& json,
	const WebSocketMessageType type)
{
	Json::FastWriter writer;
	writer.omitEndingLineFeed();
	auto msg = writer.write(json);
	notifyAllExcept(conn, msg.data(), msg.size(), type);
}
