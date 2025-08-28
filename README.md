# Vproxy

<img src="assets/logo.png" alt="Vproxy Icon" width="50"/>

[Vproxy](https://vproxy.5vnetwork.com) 是一款免费的多平台代理客户端.


## 订阅说明
Vproxy获取订阅的方式与其他代理客户端一样：从订阅链接Get到内容（如果内容是base64编码，先解码），对每一行进行解析，获取节点。 目前支持：hysteria2, ss, trojan, vless, vmess

内容的第一行可以是一句自定义的说明，比如“剩余流量：10GB，5月31日到期”。该内容将显示给用户。

## 深度链接说明
Vproxy支持用深度链接快捷导入订阅到客户端。深度链接的scheme为"vproxy"。目前支持两种格式：

1. vproxy://add/sub://<ins>aHR0cHM6Ly9leGFtcGxlLmNvbS9hYmNk</ins>?remarks=%E6%9C%BA%E5%9C%BA%0A

   下划线为base64编码的订阅地址，解码后为"https://example.com/abcd"  
   "remarks"：订阅的名称。  

2. vproxy://install-config?url=https%3A%2F%2Fexample.com%2Fabcd&name=%E6%9C%BA%E5%9C%BA%0A
   
   "name"：订阅的名称   

两个链接都会为用户添加一个名称为“机场”的订阅

## License Compliance

The code contains in "vless", "reality" and "splithttp" folder is modified from [Xray-core](https://github.com/XTLS/Xray-core). It 
is distributed under the same licence(Mozilla Public License 2.0) as the original project.
