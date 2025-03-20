#ifndef COMMON_GLOBAL_H
#define COMMON_GLOBAL_H

/* The type of the device */
enum ctx_device {
	DEVICE_ERROR            = -1,
	UNKNOWN                 = 0,
	CONNECTX                = 1,
	CONNECTX2               = 2,
	CONNECTX3               = 3,
	CONNECTIB               = 4,
	LEGACY                  = 5,
	CHELSIO_T4              = 6,
	CHELSIO_T5              = 7,
	CONNECTX3_PRO           = 8,
	SKYHAWK                 = 9,
	CONNECTX4               = 10,
	CONNECTX4LX             = 11,
	CONNECTX5		= 12,
	CONNECTX5EX		= 13,
	CONNECTX6		= 14,
	CONNECTX6DX		= 15,
	CONNECTX6LX		= 16,
	MLX5GENVF               = 17,
	BLUEFIELD3               = 18,
};

enum ctx_device ib_dev_name(struct ibv_context *context)
{
	enum ctx_device dev_fname = UNKNOWN;
	struct ibv_device_attr attr;

	if (ibv_query_device(context,&attr)) {
		dev_fname = DEVICE_ERROR;
	} else if (attr.vendor_id == 5157) {

		switch (attr.vendor_part_id >> 12) {
			case 10 :
			case 4  : dev_fname = CHELSIO_T4; break;
			case 11 :
			case 5  : dev_fname = CHELSIO_T5; break;
			default : dev_fname = UNKNOWN; break;
		}

		/* Assuming it's Mellanox HCA or unknown.
		 * If you want Inline support in other vendor devices, please send patch to gilr@dev.mellanox.co.il
		 */
	} else {
		switch (attr.vendor_part_id) {
			case 41692 : dev_fname = BLUEFIELD3; break;
			case 4127  : dev_fname = CONNECTX6LX; break;
			case 4126  : dev_fname = MLX5GENVF; break;
			case 4125  : dev_fname = CONNECTX6DX; break;
			case 4124  : dev_fname = CONNECTX6; break;
			case 4123  : dev_fname = CONNECTX6; break;
			case 4121  : dev_fname = CONNECTX5EX; break;
			case 4122  : dev_fname = CONNECTX5EX; break;
			case 4119  : dev_fname = CONNECTX5; break;
			case 4120  : dev_fname = CONNECTX5; break;
			case 4117  : dev_fname = CONNECTX4LX; break;
			case 4118  : dev_fname = CONNECTX4LX; break;
			case 4115  : dev_fname = CONNECTX4; break;
			case 4116  : dev_fname = CONNECTX4; break;
			case 4113  : dev_fname = CONNECTIB; break;
			case 4114  : dev_fname = CONNECTIB; break;
			case 4099  : dev_fname = CONNECTX3; break;
			case 4100  : dev_fname = CONNECTX3; break;
			case 4103  : dev_fname = CONNECTX3_PRO; break;
			case 4104  : dev_fname = CONNECTX3_PRO; break;
			case 26418 : dev_fname = CONNECTX2; break;
			case 26428 : dev_fname = CONNECTX2; break;
			case 26438 : dev_fname = CONNECTX2; break;
			case 26448 : dev_fname = CONNECTX2; break;
			case 26458 : dev_fname = CONNECTX2; break;
			case 26468 : dev_fname = CONNECTX2; break;
			case 26478 : dev_fname = CONNECTX2; break;
			case 25408 : dev_fname = CONNECTX;  break;
			case 25418 : dev_fname = CONNECTX;  break;
			case 25428 : dev_fname = CONNECTX;  break;
			case 25448 : dev_fname = CONNECTX;  break;
			case 1824  : dev_fname = SKYHAWK;  break;
			default    : dev_fname = UNKNOWN;
		}
	}
	return dev_fname;
}
#endif
