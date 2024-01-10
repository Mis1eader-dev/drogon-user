# Drogon User Extension
Library wrapper around the [drogon](https://github.com/drogonframework/drogon) web framework to allow for WebSocket rooms and user objects.

# Example Usage
```c++
#include "drogon-user/User.hpp"
#include "drogon/drogon.h"

int main()
{
  drogon::user::configure(...); // configure cookie
  drogon::user::configureDatabase(...); // configure database related callbacks

  drogon::app()
    .addListener("127.0.0.1", 8080)
    .run();
}
```

For WebSockets, use `WebSocketRoom` instead of `drogon::WebSocketController`:
```c++
#include "drogon-user/WebSocketRoom.hpp"
#include <iostream>

class Chat : public WebSocketRoom<Chat>
{
  void onConnect(Connect&& connect) override;
  void onMessage(Message&& message) override;
  void onDisconnect(Disconnect&& disconnect) override;

  WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/chat", "drogon::user::filter::api::LoggedIn");
  WS_PATH_LIST_END
};

void Chat::onConnect(Connect&& connect)
{
  std::cout << "New user connected with ID: " << connect.user->id() << '\n';
}

void Chat::onMessage(Message&& message)
{
  std::cout << "New message from user ID (" << message.user->id() << "): " << message.msg << '\n';
  notifyAllExcept(message.conn, message.msg);
}

void Chat::onDisconnect(Disconnect&& disconnect)
{
  std::cout << "User disconnected with ID: " << disconnect.user->id() << '\n';
}
```
