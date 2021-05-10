The code works with python3.7+ I think 

The proxy works in the following way 

```text
client application ≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁≁>target server
    |                                           ∧ 
    |                                           |
    |   socks5 protocol                         |
    |                   normal tcp data stream  |
    |                                           |
    ∨                                           |
client proxy ----------------------------> proxy server
              |addr_type|addr|port|data|
```
