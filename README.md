## About The Project
A tcp connection monitor that use libpcap to detect failed/successful TCP connections.


### Prerequisites

* glibc
  ```sh
  sudo apt-get install libglib2.0-dev
  ```
* pcap
  ```sh
  sudo apt-get install libpcap-dev
  ```

### Installation

1. Clone the repo
2. Run make
   ```sh
   cd tcp_connection_monitor
   make
   ```
## Usage
```sh
Usage ./build/tcp_monitor: <-i interface|ALL> <-t interface_type(wifi/eth)> [-s] [-o output_file] [-l log_file==stderr] [-h help]
```
Where -s option stands for "Output to stdout"

### Limitations
Does not support wireless interfaces