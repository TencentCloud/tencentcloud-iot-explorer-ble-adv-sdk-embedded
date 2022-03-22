## 说明
本工程作为`nrf52832`示例工程，最终实现使用`LLSync ADV SDK`与`腾讯连连`小程序和`腾讯云物联网平台`进行数据交互的功能。

## 移植适配
* 此sample使用的nrf SDK版本为`nRF5_SDK_17.1.0_ddde560`, 请自行前往[NORDIC 官网](https://www.nordicsemi.com/Products/nRF52832/Download#infotabs)进行下载。
* 拷贝`qcloud-iot-ble-adv-nrf52832`文件夹至`nRF5_SDK_17.1.0_ddde560\examples\ble_peripheral\`目录下。
* 打开工程`nRF5_SDK_17.1.0_ddde560\examples\ble_peripheral\qcloud-iot-ble-adv-nrf52832\pca10040\s132\arm5_no_packs\ble_app_beacon_pca10040_s132.uvprojx`。
* 编译下载