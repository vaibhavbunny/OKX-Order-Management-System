# OKX C++ Trading Client

This project provides a C++ client for interacting with the [OKX Exchange API](https://www.okx.com/docs-v5/en/), supporting authenticated trading operations and market data retrieval. It includes modular components for order handling and client configuration.

## 📁 Project Structure

```

.
├── CMakeLists.txt           # CMake build configuration
├── OKXOrderSystem.cpp       # High-level order management logic
├── Okx\_client.cpp           # OKXClient class implementation (API interaction)
├── okx\_client.h             # Header for OKXClient class
├── README.md                # Project documentation

````

## ✅ Features

- Place spot or futures orders (`limit` / `market`).
- Modify open orders (update size or price).
- Cancel open orders using `order_id` or `client_order_id`.
- Fetch:
  - Open/pending orders
  - Order history
  - Market order book
  - Current open positions
- Built-in support for simulated trading via `x-simulated-trading: 1` header.

## ⚙️ Build Instructions

### Prerequisites

- **C++17** or higher
- **CMake** ≥ 3.10
- [libcurl](https://curl.se/libcurl/) and [OpenSSL](https://www.openssl.org/)
- [nlohmann/json](https://github.com/nlohmann/json) (header-only)

### 📦 Install Dependencies

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install libssl-dev libcurl4-openssl-dev
````

#### macOS

```bash
brew install openssl curl
```

### 🏗️ Build & Run

```bash
git clone https://github.com/yourusername/okx-cpp-client.git
cd okx-cpp-client
mkdir build && cd build
cmake ..
make
./okx_client_app
```

> Make sure to update `main.cpp` or `OKXOrderSystem.cpp` to call functions you wish to test.

## 🚀 Example Usage

```cpp
#include "okx_client.h"

int main() {
    OKXClient client("API_KEY", "SECRET_KEY", "PASSPHRASE");

    // Place a limit buy order
    client.placeOrder("BTC-USDT", "buy", "limit", 0.001, 30000);

    // Cancel an order
    client.cancelOrder("BTC-USDT", "order_id_here", "");

    // Fetch order book
    std::string book = client.getOrderBook("BTC-USDT");
    std::cout << book << std::endl;

    return 0;
}
```

## 📄 File Overview

| File                 | Purpose                                       |
| -------------------- | --------------------------------------------- |
| `Okx_client.cpp`     | Implements HTTP communication with OKX API    |
| `okx_client.h`       | Defines the OKXClient class and utilities     |
| `OKXOrderSystem.cpp` | Optional high-level wrapper or strategy logic |
| `CMakeLists.txt`     | CMake config for building the project         |

## 🛡️ Disclaimer

This client is provided for educational and testing purposes. Always test on **simulated trading** first before using real funds.

## 📜 License

MIT License. See `LICENSE` file (if available).

