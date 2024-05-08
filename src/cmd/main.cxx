#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/pkg/client.hpp"

/*
 * Usage: ./signal <accept|connect> [address] [port]
 * Ex: ./signal accept localhost 3000
 *     ./signal connect localhost 3000
 */
int main(int argc, char *argv[]) {
  // Input checking.
  if (argc != 4) {
    std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port]"
              << std::endl;
    return 1;
  }
  std::string command = argv[1];
  std::string address = argv[2];
  int port = atoi(argv[3]);
  if (command != "listen" && command != "connect") {
    std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port]"
              << std::endl;
    return 1;
  }

  // Connect to network driver.
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  if (command == "listen") {
    network_driver->listen(port);
  } else if (command == "connect") {
    network_driver->connect(address, port);
  } else {
    throw std::runtime_error("Error: got invalid client command.");
  }
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  // Create client then run network, crypto, and cli.
  Client client = Client(network_driver, crypto_driver);
  client.run(command);
  return 0;
}
