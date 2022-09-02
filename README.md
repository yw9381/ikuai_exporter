# ikuai 监控exporter

本项目为ikuai软路由提供了用于Prometheus采集的Exporter

## 环境变量

|变量名|变量值举例|是否必有|说明|
|--|--|--|--|
| IK_USERNAME | admin | 是 | iKuai 登录的用户名 |
| IK_PASSWORD | admin | 是 | iKuai 登录的密码 |
| IK_IPADDR | 192.168.1.1 | 是 | iKuai的访问地址 |
| IK_MGR_PORT | 8443 | 否 | 管理页面端口 |
| IK_USE_HTTPS | true | 否 | 是否启用HTTPS访问 |

## 构建

```bash
docker build . -t ikuai_exporter
```

## 使用

### docker

```bash
docker run -dit -e IK_USERNAME=admin -e IK_PASSWORD=admin -e IK_IPADDR=192.168.1.1 -p 9000:9000 ikuai_exporter
```

### docker-compose

```bash
docker-compose build
docker-compose up -d
```

### Kubernetes

请参考`k8s_apply.yml`自行根据需求修改

```
kubectl apply k8s_apply.yml
```

## 获取数据

访问`/metrics`即可获取数据

## 服务状态监测

访问`/ping` 如回复为`pong`则证明服务正常