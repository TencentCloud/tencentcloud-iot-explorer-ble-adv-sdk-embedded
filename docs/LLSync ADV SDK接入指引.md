## LLSync ADV SDK接入指引

本文档旨在对LLSync ADV 广播移植适配的过程做一说明，包括：概念简介、移植说明、注意事项等。

### 一、概念简介

LLSync ADV SDK利用BLE广播能力通信，无需蓝牙连接，适用于开关控制等简单应用场景。腾讯连连小程序已经实现了LLSync 广播协议，您只需要在设备端适配 LLSync ADV SDK 即可完成与小程序/腾讯云物联网开发平台的交互。

![](https://main.qcloudimg.com/raw/42738f716556189263fd6e690f50d7ca.png)

### 二、硬件设备选择

`LLSync ADV SDK`的资源需求如下，请您结合自身产品特性选择合适的硬件设备。

| 资源名称  | 推荐要求 |
| :-------- | :------- |
| BLE协议栈 | ≥BLE 4.2 |
| Flash     | 10KByte  |
| RAM       | 1KByte   |

*以上资源占用是LLSync全功能版本在`nrf52832`上统计得到，不同硬件平台可能存在差异，该数据仅供参考。*

### 三、控制台创建产品

1. 登录[物联网开发平台](https://console.cloud.tencent.com/iotexplorer)。
2. 选择[新建项目](https://cloud.tencent.com/document/product/1081/50969#.E6.96.B0.E5.BB.BA.E9.A1.B9.E7.9B.AE)。
3. [创建产品](https://cloud.tencent.com/document/product/1081/50969#.E6.96.B0.E5.BB.BA.E4.BA.A7.E5.93.81)，通信方式选择`BLE`。
4. 根据产品特性添加[数据模板](https://cloud.tencent.com/document/product/1081/50969#.E5.88.9B.E5.BB.BA.E6.95.B0.E6.8D.AE.E6.A8.A1.E6.9D.BF)(注意数据类型只支持整型、布尔和枚举)。
5. [创建设备](https://cloud.tencent.com/document/product/1081/50969#.E6.96.B0.E5.BB.BA.E8.AE.BE.E5.A4.87)。

### 四、移植SDK

1. 配置参数编写

   编辑`config/ble_qiot_adv_config.h`文件，进行功能配置。

   ```c
    /* 设备是否同时支持扫描和广播，如果支持填1，否则填0 */
    #ifndef LLSYNC_DEV_ADV_AND_SCAN
    #define LLSYNC_DEV_ADV_AND_SCAN 1
    #endif

    /* 设备广播的最小周期：32*0.625=20ms */
    #define LLSYNC_ADV_INTERVAL         (0x20)

    /* 设备的扫描串口和扫描间隔，根据实际设备和接口进行适配，注意扫描间隔不能大于扫描窗口 */
    #define LLSYNC_SCAN_WINDOW      (0x10)
    #define LLSYNC_SCAN_INTERVAL    (0x10)

    /* 定时器的周期(ms) */
    #define LLSYNC_ADV_TIMER_INTERVAL             (10)

    /* 设备数据存储地址 */
    #define LLSYNC_ADV_RECORD_FLASH_ADDR      0x7e000  // qiot data storage address
    #define LLSYNC_ADV_RECORD_FLASH_PAGESIZE  4096     // flash page size, see chip datasheet

    /* 设备打印口适配 */
    #define LLSYNC_ADV_LOG_PRINT(...)        printf(__VA_ARGS__)
   ```

2. 设备接口适配
   
   `include/ble_qiot_adv_import.h`中定义了`LLSync ADV SDK`依赖的设备`HAL`实现，需要您在自己的硬件平台上进行实现。

   ```c
   /* 定时器创建接口示例：
   typedef struct ble_esp32_timer_id_ {
       uint8_t       type;
       ble_timer_cb  handle;
       TimerHandle_t timer;
   } ble_esp32_timer_id;
   ble_timer_t llsync_timer_create(uint8_t type, ble_timer_cb timeout_handle)
   {
       ble_esp32_timer_id *p_timer = malloc(sizeof(ble_esp32_timer_id));
       if (NULL == p_timer) {
           return NULL;
       }
       p_timer->type   = type;
       p_timer->handle = timeout_handle;
       p_timer->timer  = NULL;
       return (ble_timer_t)p_timer;
   }
   此处的timeout handle为：llsync_adv_timer_cb
   */
   ble_timer_t llsync_timer_create(uint8_t type, ble_timer_cb timeout_handle);

    /* 定时器启动接口示例：
   ble_qiot_ret_status_t llsync_timer_start(ble_timer_t timer_id, uint32_t period)
   {
       ble_esp32_timer_id *p_timer = (ble_esp32_timer_id *)timer_id;
       if (NULL == p_timer->timer) {
           p_timer->timer =
               (ble_timer_t)xTimerCreate("ota_timer", period / portTICK_PERIOD_MS,
   									p_timer->type == BLE_TIMER_PERIOD_TYPE ? pdTRUE : pdFALSE, NULL, p_timer->handle);
       }
       xTimerReset(p_timer->timer, portMAX_DELAY);
       return BLE_QIOT_RS_OK;
   }
   */
   ble_qiot_ret_status_t llsync_timer_start(ble_timer_t timer_id, uint32_t period);

    /* 定时器停止接口示例：
   ble_qiot_ret_status_t llsync_timer_stop(ble_timer_t timer_id)
   {
       ble_esp32_timer_id *p_timer = (ble_esp32_timer_id *)timer_id;
       xTimerStop(p_timer->timer, portMAX_DELAY);
       return BLE_QIOT_RS_OK;
   }
   */
   ble_qiot_ret_status_t llsync_timer_stop(ble_timer_t timer_id);

    /* 获取设备信息示例:
    #define PRODUCT_ID  "9ESYQHPQF3"
    #define DEVICE_NAME "ty"
    #define SECRET_KEY  "uvGt+pro0A84Ckftsbd0XQ=="
    ble_qiot_ret_status_t llsync_get_dev_info(ble_device_info *dev_info)
    {
        char *address = (char *)esp_bt_dev_get_address();
        memcpy(dev_info->mac, address, 6);
        memcpy(dev_info->product_id, PRODUCT_ID, strlen(PRODUCT_ID));
        memcpy(dev_info->device_name, DEVICE_NAME, strlen(DEVICE_NAME));
        memcpy(dev_info->psk, SECRET_KEY, strlen(SECRET_KEY));

        return BLE_QIOT_RS_OK;
    }
    */
    ble_qiot_ret_status_t llsync_get_dev_info(ble_device_info_t *dev_info);

    /* flash操作示例:
    int llsync_flash_deal(llsync_flash_e type, uint32_t flash_addr, char *buf, uint16_t len)
    {
        int ret = 0;
        return len;
        if (LLSYNC_ADV_WRITE_FLASH == type) {
            ret = spi_flash_erase_range(flash_addr, BLE_QIOT_RECORD_FLASH_PAGESIZE);
            ret     = spi_flash_write(flash_addr, buf, len);
        } else if(LLSYNC_ADV_READ_FLASH == type){
            ret = spi_flash_read(flash_addr, buf, len);
        }

        return ret == ESP_OK ? len : ret;
    }
    */
    int llsync_flash_handle(e_llsync_flash_user type, uint32_t flash_addr, char *buf, uint16_t len);

    /* 广播操作示例:
    ble_qiot_ret_status_t llsync_adv_deal(llsync_adv_e type, uint8_t *data_buf, uint8_t data_len)
    {
        if (LLSYNC_ADV_START == type) {
            esp_err_t ret = esp_ble_gap_config_adv_data_raw(data_buf, data_len);
            if (ret) {
                ble_qiot_log_i("config adv data failed, error code = %x", ret);
            }
        } else if (LLSYNC_ADV_STOP == type){
            esp_ble_gap_stop_advertising();
        }

        return BLE_QIOT_RS_OK;
    }
    */
    ble_qiot_ret_status_t llsync_adv_handle(e_llsync_adv_user type, uint8_t *data_buf, uint8_t data_len);

    /* 设备不同阶段提示:
    ble_qiot_ret_status_t llsync_dev_operate_deal(llsync_dev_operate_e type)
    {
        ble_qiot_ret_status_t ret = BLE_QIOT_RS_OK;

        if (LLSYNC_ADV_DEV_START_NET_HINT == type) {
            //开始配网提示
        } else if (LLSYNC_ADV_DEV_AGREE_NET_HINT == type) {
            //同意配网提示 0：同意   非0：不同意
        } else if (LLSYNC_ADV_DEV_DELETE_HINT == type){
            //删除配网提示
        }

        return BLE_QIOT_RS_OK;
    }
    */
    ble_qiot_ret_status_t llsync_dev_operate_handle(e_llsync_dev_operate_user type);

    /* 扫描函数示例:
    ble_qiot_ret_status_t llsync_scan_deal(llsync_scan_e type)
    {
        if (LLSYNC_SCAN_START == type) {
            esp_ble_gap_set_scan_params(&ble_scan_params);
        } else if (LLSYNC_SCAN_STOP == type){
            esp_ble_gap_stop_scanning();
        }

        return BLE_QIOT_RS_OK;
    }
    */
    ble_qiot_ret_status_t llsync_scan_handle(e_llsync_scan_user type);
    
    /* 预留给用户的初始化函数，设备启动时调用，不可死循环 */
    void llsync_adv_user_ex_init(void);
    
   ```

3. API调用
    
    include/ble_qiot_adv_export.h中定义了LLSync SDK对外提供的API。
    
    ```c
    /* 扫描数据解析接口，将扫描到的数据通过此接口送入SDK进行解析，需要保证scan到的数据符合 AD Structure类型 */
    ble_qiot_ret_status_t ble_scan_data_analyze(uint8_t *buf, uint8_t buf_len);

    /* 定时器回调函数，入参置NULL，此函数调用周期是LLSYNC_ADV_TIMER_INTERVAL */
    void llsync_adv_timer_cb(void *param);

    /* 属性上报接口，上报设备最新的状态 */
    ble_qiot_ret_status_t llsync_adv_property_report(void);
    ```

4. 数据模板开发

   llsync广播SDK提供了`Python`脚本，可以快速将`Json`格式的数据模板转换为`C`代码模板，提升您的开发效率。具体请参考SDK中`scripts`文件夹相关内容。

   其中，`example.json`是您的物模型`json`文本文件，命令执行结束会生成模板文件`ble_qiot_template.c`和`ble_qiot_template.h`文件，`ble_qiot_template.c`需要您做应用代码实现。示例：

   物模型内容如下：

   ```json
   {
    "id": "switch",
    "name": "开关",
    "desc": "",
    "mode": "rw",
    "define": {
    "type": "bool",
    "mapping": {
    "0": "关",
    "1": "开"
    }
    },
    "required": false
    }
   ```

   经过脚本转换后，在`ble_qiot_template.c`中对应`C`代码如下：

   ```c
   static int ble_property_switch_set(const char *data, uint16_t len)
   {
       return 0;
   }
   static int ble_property_switch_get(char *data, uint16_t buf_len)
   {
       return sizeof(uint8_t);
   }
   ```

   假设该物模型对应的是灯泡开关功能，您只需要在`ble_property_switch_set`函数中进行灯泡开关控制，在`ble_property_switch_get`函数中获取灯泡实时状态即可。

   ```c
   static bool     sg_switch     = 0;
   static int ble_property_switch_set(const char *data, uint16_t len)
   {
       sg_switch = data[0];
     	if (sg_switch){
         open_light();
       }else{
         close_light();
       }
       return 0;
   }
   static int ble_property_switch_get(char *data, uint16_t buf_len)
   {
       data[0] = sg_switch;
       return sizeof(uint8_t);
   }
   ```

### 五、BLE功能验证

​	您完成LLSync ADV SDK移植后，首先需要确保定时器的功能是完整的，因为LLSync ADV SDK一切功能都是以定时器为基准。

 1. 未配网广播，可以使用nrf connect进行扫描查看。

    ![](https://main.qcloudimg.com/raw/d6e80d92245095eac7d0dc9567d9815d.png)

    对广播数据中标出的字段进行解析。

    |名称          | 字段值                  | 含义               |
    |---           | -----------------------| -------------------|
    |CID           | 0xFEBA                 | LLSync广播标识  |
    |Frame Control | 0x8000                 | 用来识别beacon作用，bit 15 表示这是 标准广播协议，3 ～ 0 表示版本号。 |
    |MAC[4:5]      | 0xB5E1                 | 设备MAC地址最后2个字节 |
    |PID           | 0x39455359514850514633 | Product ID:9ESYQHPQF3 |
    |Dev name len  | 0x02                   |设备名称长度            |
    |Dev Name      | 0x6877                  |设备名称：hw            |
    |SplitCycle    | 0x28                    |小程序分片时间周期(单位:10ms)|
2. 如果上述未配网广播数据已经适配成功，接下来则可以直接使用腾讯连连进行进一步的设备功能验证，使用腾讯连连`添加设备`功能就可以看到正在广播未配网数据的设备，进行添加、控制即可。

### 六、注意事项
1. 在腾讯云平台进行设备创建时，注意device name的长度不能超过8 Bytes；
2. llsync广播支持的数据类型为：布尔、整型和枚举，故在创建产品时注意选择相应的数据类型；
3. llsync广播支持的最大数据长度为124 Bytes;
4. 广播类型需要设置为不可连接、不可扫描的非定向型广播。
