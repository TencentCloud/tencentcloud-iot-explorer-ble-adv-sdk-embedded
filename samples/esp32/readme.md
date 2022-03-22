## 说明
本工程作为`esp32`示例工程，最终实现使用`LLSync ADV SDK`与`腾讯连连`小程序和`腾讯云物联网平台`进行数据交互的功能。

## 编译指导
1. 安装`ESP-IDF`，请参考[官网文档](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html#step-2-get-esp-idf)
```c
mkdir -p ~/esp
cd ~/esp
git clone --recursive https://github.com/espressif/esp-idf.git
```

2. 拷贝`qcloud-iot-ble-adv-esp32`组件到`ESP-IDF`目录下

```c
cp -r qcloud-iot-ble-esp32 $IDF_PATH
cd $IDF_PATH/qcloud-iot-ble-esp32
```
3. 登陆[物联网开发平台](https://cloud.tencent.com/product/iotexplorer), 使用`components/qcloud_llsync/data_template/esp32.json`作为数据模版创建设备。
   使用新设备的三元信息替换`components/qcloud_llsync/hal/ble_qiot_ble_device.c`中宏定义中的设备信息，编译并烧录到开发板。

```c
idf.py flash
```
4. 打开腾讯连连小程序，添加设备，观察串口输出和腾讯云物联网开发平台上的设备日志。