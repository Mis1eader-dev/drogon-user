#include "drogon-user/Room.hpp"
#include "drogon-user/User.hpp"
#include "drogon/HttpAppFramework.h"
#include "drogon/WebSocketConnection.h"
#include "trantor/net/EventLoop.h"
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <utility>

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
	OfflineUserCallback offlineUserCallback_ = nullptr;
#endif
}

Room::Room() :
	users_()
{}

Room::Room(std::unordered_map<std::string_view, UserPtr>&& users) :
	users_(users)
{}

UserPtr User::create(string_view id)
{
	UserPtr user = std::make_shared<User>(string(id));

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

void User::enqueueForPurge(string_view id)
{
	scoped_lock lock(::timeoutsMutex_);
	::timeouts_.insert(
		std::make_pair(
			id,
			drogon::app().getLoop()->runAfter(
				user::userCacheTimeout_,
				[id]()
				{
				#ifdef ENABLE_OFFLINE_CALLBACK
					if(user::offlineUserCallback_)
						user::offlineUserCallback_(
							std::move(get(id))
						);
				#endif

					// User becomes offline here
					{
						scoped_lock lock(::mutex_);
						::allUsers_.erase(id);
					}

					scoped_lock lock(::timeoutsMutex_);
					::timeouts_.erase(id);
				}
			)
		)
	);
}

UserPtr User::get(string_view id)
{
	shared_lock lock(::mutex_);
	auto find = ::allUsers_.find(id);
	return find != ::allUsers_.end() ? find->second : nullptr;
}
UserPtr User::get(const HttpRequestPtr& req)
{
	return std::move(get(user::getId(req)));
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
			// Pointer transfer
			id = user->id();

			{
				auto& mtx = user->mutex_;
				mtx.lock_shared();
				bool isOrphan = user->conns_.empty();
				mtx.unlock_shared();
				if(isOrphan)
				{
					decltype(::timeouts_.find(id)) find;
					{
						shared_lock slock(::timeoutsMutex_);
						find = ::timeouts_.find(id);
					}
					drogon::app().getLoop()->invalidateTimer(find->second);

					scoped_lock lock(::timeoutsMutex_);
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
			user = std::move(User::create(id, conn, this));
	}

	conn->setContext(user);
	return std::move(user);
}

UserPtr Room::get(std::string_view id) const
{
	shared_lock lock(mutex_);
	auto find = users_.find(id);
	return find != users_.end() ? find->second : nullptr;
}
UserPtr Room::get(const HttpRequestPtr& req) const
{
	return std::move(get(user::getId(req)));
}
UserPtr Room::get(const WebSocketConnectionPtr& conn) const
{
	return conn->getContext<User>();
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

	auto& mtx = user->mutex_;
	auto& connsMap = user->conns_;

	shared_lock slock(mtx);
	auto find = connsMap.find(this);
	if(find == connsMap.end())
		return std::move(user);

	auto& connsSet = find->second;
	if(connsSet.size() == 1) // Final connection to room
	{
		string_view id = user->id();
		if(connsMap.size() == 1) // Final connection to server
		{
			slock.unlock();
			{
				scoped_lock lock(mtx);
				connsMap.clear();
			}

			User::enqueueForPurge(id);
		}
		else
		{
			slock.unlock();

			scoped_lock lock(mtx);
			connsMap.erase(this);
		}

		scoped_lock lock(mutex_);
		users_.erase(id);
	}
	else
	{
		slock.unlock();

		scoped_lock lock(mtx);
		connsSet.erase(conn);
	}

	return std::move(user);
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

void Room::notifyAll(const char* msg, uint64_t len,
	const WebSocketMessageType type)
{
	shared_lock lock(mutex_);
	for(const auto& [_, user] : users_)
		notify(user, msg, len, type);
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
