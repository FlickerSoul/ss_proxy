## Introduction
The code works with python3.7+ I think 

The proxy works in the following way 

```text
client application ≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁> target server
    |               redirected connection       ∧ 
    |                                           |
    |   socks5 protocol                         |
    |                   normal tcp data stream  |
    |                                           |
    ∨                                           |
proxy client -----------------------------> proxy server
              |addr_type|addr|port|data|
```

## Usage

basic usage: 
```bash
python3 main.py [-h] [--config CONFIG] [--level {info,debug,warn,error}] [--version] {server,client}
```

Example: 

```bash
python3 main.py server --config configs.ServerConfig -l debug  # open a server
```

```bash
python3 main.py server --config configs.LocalClientConfig -l debug  # open a local client 
```

The configurations for proxy server and proxy client are located `configs.py`. There are three default configurations: `ServerConfig`, `LocalClientConfig`, and `RemoteClientConfig`. 

The proxy server config tells the server to open a socket at `local_port  ` to accept proxy client requests. The `address` and `port` in the proxy client config tells the client to connect to proxy server at `address:prot` and open a socket at `local_port` to receive socks5 requests from applications clients. 

You can create your own configuration class by inheriting the `BaseConfig` in `configs.py` file. 

You can specify the config class by using `--config module_path.class_name`.

The `--level` or `-l` flag specifies the log output level. 

To use socks5 to connect to client: 

```bash
export all_proxy=socks5://127.0.0.1:<local_port>
```

Example:
```bash
export all_proxy=socks5://127.0.0.1:7690  # for the LocalServer configuration
```
