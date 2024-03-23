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

static std::shared_mutex timeoutsMutex_;
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

UserPtr User::create(string&& id)
{
	UserPtr user = std::make_shared<User>(std::move(id));

	auto pair = std::make_pair(user->id(), user);
	{
		scoped_lock lock(::mutex_);
		::allUsers_.insert(std::move(pair));
	}

	return std::move(user);
}
UserPtr User::create(string_view id, const WebSocketConnectionPtr& conn, Room* room)
{
	UserPtr user = std::make_shared<User>(string(id), conn, room);

	auto pair = std::make_pair(user->id(), user);
	{
		scoped_lock lock(room->mutex_);
		room->users_.insert(pair);
	}
	{
		scoped_lock lock(::mutex_);
		::allUsers_.insert(std::move(pair));
	}

	return std::move(user);
}

static inline trantor::TimerId enqueuePurge(string_view id)
{
	return drogon::app().getLoop()->runAfter(
		user::userCacheTimeout_,
		[id]()
		{
			{
			#ifdef ENABLE_OFFLINE_CALLBACK
				UserPtr user = User::get(id);
			#endif

				{
					scoped_lock lock(::mutex_);
					::allUsers_.erase(id);
				}

			#ifdef ENABLE_OFFLINE_CALLBACK
				for(const auto& cb : user::offlineUserCallbacks_)
					cb(user);
			#endif
			}

			scoped_lock lock(::timeoutsMutex_);
			::timeouts_.erase(id);
		}
	);
}

void User::enqueueForPurge(string_view id)
{
	scoped_lock lock(::timeoutsMutex_);
	::timeouts_.insert(
		std::make_pair(
			id,
			enqueuePurge(id)
		)
	);
}

void User::prolongPurge(string_view id)
{
	scoped_lock lock(::timeoutsMutex_);
	auto find = ::timeouts_.find(id);
	if(find == ::timeouts_.end())
		return;

	drogon::app().getLoop()->invalidateTimer(find->second);
	find->second = enqueuePurge(id);
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

	{
	#ifdef ENABLE_OFFLINE_CALLBACK
		UserPtr user = get(id_);
	#endif

		{
			scoped_lock lock(mutex_);
			for(const auto& [_, conns] : conns_)
				manualClosures_ += conns.size();

			for(const auto& [_, conns] : conns_)
				for(const WebSocketConnectionPtr& conn : conns)
					conn->forceClose();

			{ // wait until all disconnect callbacks have finished
				std::unique_lock lock(manualClosuresMutex_);
				manualClosuresCv_.wait(lock, [this]() -> bool
				{
					return manualClosures_ == 0;
				});
			}

			for(const auto& [room, _] : conns_)
			{
				scoped_lock lock(room->mutex_);
				room->users_.erase(id_);
			}

			conns_.clear();
		}

		{
			scoped_lock lock(::mutex_);
			::allUsers_.erase(id_);
		}

	#ifdef ENABLE_OFFLINE_CALLBACK
		for(const auto& cb : user::offlineUserCallbacks_)
			cb(user);
	#endif
	}
}

UserPtr User::get(string_view id, bool extendLifespan)
{
	shared_lock lock(::mutex_);
	auto find = ::allUsers_.find(id);
	if(find == ::allUsers_.end())
		return nullptr;

	UserPtr user = find->second;
	if(extendLifespan)
		User::prolongPurge(user->id_);
	return std::move(user);
}

UserPtr Room::add(const HttpRequestPtr& req, const WebSocketConnectionPtr& conn)
{
	string_view id = user::getId(req);
	UserPtr user = get(id);
	if(user) // Available in current room
	{
		scoped_lock lock(user->mutex_);
		user->conns_[this].insert(conn);
	}
	else
	{
		user = User::get(id);
		if(user) // Available in memory
		{
			// Pointer copy
			id = user->id();

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
				user->conns_.insert(
					std::move(
						std::pair<Room*, User::ConnsSet>(
							this, {
								conn
							}
						)
					)
				);
			}

			scoped_lock lock(mutex_);
			users_.insert(
				std::move(
					std::make_pair(id, user)
				)
			);
		}
		else // Unavailable anywhere
			user = std::move(
				User::create(
					string(id),
					conn,
					this
				)
			);
	}

	conn->setContext(user);
	return std::move(user);
}

UserPtr Room::get(std::string_view id, bool extendLifespan) const
{
	UserPtr user = nullptr;
	{
		shared_lock lock(mutex_);
		auto find = users_.find(id);
		if(find == users_.end())
			return std::move(user);

		user = find->second;
	}
	if(extendLifespan)
		User::prolongPurge(user->id_);
	return std::move(user);
}

UserPtr Room::remove(const UserPtr& user)
{
	{
		scoped_lock lock(user->mutex_);
		user->conns_.erase(this);
	}
	{
		scoped_lock lock(mutex_);
		users_.erase(user->id());
	}
	return std::move(user);
}
UserPtr Room::remove(const WebSocketConnectionPtr& conn)
{
	UserPtr user = get(conn);
	if(user->manualClosures_ > 0)
	{
		--(user->manualClosures_);
		user->manualClosuresCv_.notify_all();
		return nullptr;
	}

	auto& mtx = user->mutex_;
	auto& connsMap = user->conns_;

	string_view id;
	{
		scoped_lock lock(mtx);
		auto find = connsMap.find(this);
		if(find == connsMap.end())
			return std::move(user);

		auto& connsSet = find->second;
		if(connsSet.size() == 1) // Final connection to room
		{
			id = user->id();
			if(connsMap.size() == 1) // Final connection to server
			{
				connsMap.clear();
				User::enqueueForPurge(id);
			}
			else
				connsMap.erase(this);
		}
		else
			connsSet.erase(conn);
	}

	if(!id.empty())
	{
		scoped_lock lock(mutex_);
		users_.erase(id);
	}

	return std::move(user);
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
	shared_lock lock(user->mutex_);
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
	shared_lock lock(mutex_);
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
	shared_lock lock(mutex_);
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
	shared_lock lock(user->mutex_);
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
