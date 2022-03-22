if (CONFIG_QCLOUD_LLSYNC_SUPPORT)
    set(srcs
			sdk_src/src/ble_qiot_adv_center.c
			sdk_src/src/ble_qiot_adv_ctrl.c
			sdk_src/src/ble_qiot_adv_property.c
			sdk_src/utils/ble_qiot_aes.c
			sdk_src/utils/ble_qiot_utils_log.c
			sdk_src/utils/ble_qiot_utils_md5.c
			sdk_src/utils/ble_qiot_utils_data.c
			sdk_src/utils/ble_qiot_fifo.c)

    list(APPEND srcs
            data_template/ble_qiot_template.c
	    hal/ble_qiot_adv_external.c)

    set(includes include sdk_src/internal_inc)
    set(priv_includes data_template cfg sdk_src/internal_inc)

endif ()

idf_component_register(SRCS "${srcs}"
        INCLUDE_DIRS "${includes}"
        PRIV_INCLUDE_DIRS "${priv_includes}"
        REQUIRES bt app_update)
