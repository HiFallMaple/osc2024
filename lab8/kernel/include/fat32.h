
#include "stdint.h"
#include "vfs.h"

#define BLOCK_SIZE 512
#define FAT32_MAX_FILENAME 8
#define FAT32_MAX_EXTENSION 3

#define FAT32_FREE_CLUSTER 0x00000000
#define FAT32_BAD_CLUSTER 0x0FFFFFF7
#define FAT32_END_OF_CHAIN 0x0FFFFFF8

struct partition_entry
{
	uint8_t status;			// 引導標誌，0x80代表引導分區，0x00代表非引導分區
	uint8_t start_head;		// 起始柱面頭部
	uint8_t start_sector;	// 起始扇區
	uint8_t start_cylinder; // 起始柱面
	uint8_t type;			// 分區類型
	uint8_t end_head;		// 結束柱面頭部
	uint8_t end_sector;		// 結束扇區
	uint8_t end_cylinder;	// 結束柱面
	uint32_t start_lba;		// 起始邏輯區塊地址
	uint32_t size;			// 分區大小（以扇區數為單位）
} __attribute__((packed));

// MBR format
// 000 ~ 1BD: Code area
// 1BE ~ 1FD: Master Partition Table
// 1FE ~ 1FF: Boot Record Signature
struct MBR
{
	uint8_t bootstrap_code[0x1BE];			   // 引導代碼區塊
	struct partition_entry partition_table[4]; // 分區表，共4個分區
	uint16_t signature;						   // MBR簽名，0x55AA
} __attribute__((packed));

struct bpb_fat32
{									// 68
	uint8_t jump_boot[3];			// 跳躍指令，用於跳過 BPB 並跳轉到引導代碼
	uint8_t oem_name[8];			// OEM 名稱，通常是文件系統創建工具的名稱
	uint16_t bytes_per_sector;		// 每扇區字節數，通常為 512
	uint8_t sectors_per_cluster;	// 每簇扇區數
	uint16_t reserved_sector_count; // 保留扇區數，包括引導扇區和其他系統用途的扇區
	uint8_t num_fats;				// FAT 表數量，通常為 2
	uint16_t root_entry_count;		// 根目錄條目數，FAT32 中為 0
	uint16_t total_sectors_16;		// 總扇區數（小於 32MB 時使用）
	uint8_t media;					// 媒體描述符
	uint16_t fat_size_16;			// 每個 FAT 表的扇區數（FAT32 中為 0）
	uint16_t sectors_per_track;		// 每磁道扇區數（用於 CHS 尋址）
	uint16_t num_heads;				// 磁頭數（用於 CHS 尋址）
	uint32_t hidden_sectors;		// 隱藏扇區數，文件系統開始前的扇區數
	uint32_t total_sectors_32;		// 總扇區數（大於 32MB 時使用）
	uint32_t fat_size_32;			// 每個 FAT 表的扇區數
	uint16_t ext_flags;				// 擴展標誌
	uint16_t fs_version;			// 文件系統版本
	uint32_t root_cluster;			// 根目錄的起始簇號
	uint16_t fs_info;				// 文件系統信息扇區號
	uint16_t backup_boot_sector;	// 備份引導扇區號
	uint8_t reserved[12];			// 保留字節
	uint8_t drive_number;			// 驅動器號
	uint8_t reserved1;				// 保留（必須為 0）
	uint8_t boot_signature;			// 擴展引導標記（必須為 0x29）
	uint32_t volume_id;				// 卷序列號
	uint8_t volume_label[11];		// 卷標
	uint8_t fs_type[8];				// 文件系統類型（字符串 "FAT32"）
	uint8_t boot_code[420];			// 引導代碼
	uint16_t boot_sector_signature; // 引導扇區結束標誌（0xAA55）
} __attribute__((packed));

// FAT32 FSINFO structure
struct fs_info {
    uint32_t lead_signature;        // Should be 0x41615252
    uint8_t  reserved1[480];        // Must be zero
    uint32_t structure_signature;   // Should be 0x61417272
    uint32_t free_count;            // Number of free clusters; -1 if unknown
    uint32_t next_free;             // Next free cluster; 0xFFFFFFFF if unknown
    uint8_t  reserved2[12];         // Must be zero
    uint32_t trail_signature;       // Should be 0xAA550000
} __attribute__((packed));

struct sfn_entry
{
	uint8_t name[FAT32_MAX_FILENAME];		// 文件名，最多8個字節，不足部分使用空格填充
	uint8_t extension[FAT32_MAX_EXTENSION]; // 文件擴展名，最多3個字節，不足部分使用空格填充
	uint8_t attribute;						// 屬性
	uint8_t reserved;						// 保留位
	uint8_t creation_time_tenth_seconds;	// 創建時間的1/10秒計數
	uint16_t creation_time;					// 創建時間
	uint16_t creation_date;					// 創建日期
	uint16_t last_access_date;				// 最後訪問日期
	uint16_t first_cluster_high;			// 文件起始簇高16位
	uint16_t last_write_time;				// 最後修改時間
	uint16_t last_write_date;				// 最後修改日期
	uint16_t first_cluster_low;				// 文件起始簇低16位
	uint32_t file_size;						// 文件大小（字節）
} __attribute__((packed));

typedef struct fat32_inode
{
	vnode_list_t *child_list;
	char name[MAX_FILE_NAME]; // Name              : represents file name
	char *data;				  // Data              : represents file data in memory
	uint32_t first_cluster;	  // First Cluster     : represents the first cluster of the file
	uint32_t filesize;		  // File Size         : represents the size of the file
} fat32_inode_t;

int register_fat32();
int fat32_setup_mount(filesystem_t *fs, mount_t *_mount, vnode_t *parent, const char *name);
vnode_t *fat32_create_vnode(mount_t *superblock, enum fsnode_type type, vnode_t *parent, const char *name, uint32_t first_cluster, uint32_t filesize);
fat32_inode_t *fat32_create_inode(enum fsnode_type type, const char *name, uint32_t first_cluster, uint32_t filesize);

int fat32_write(struct file *file, const void *buf, size_t len);
int fat32_read(struct file *file, void *buf, size_t len);
int fat32_open(struct vnode *file_node, struct file **target);
int fat32_close(struct file *file);
long fat32_lseek64(struct file *file, long offset, int whence);
long fat32_getsize(struct vnode *vd);

int fat32_lookup(struct vnode *dir_node, struct vnode **target, const char *component_name);
int fat32_create(struct vnode *dir_node, struct vnode **target, const char *component_name);
int fat32_mkdir(struct vnode *dir_node, struct vnode **target, const char *component_name);
int __fat32_mkdir(struct vnode *dir_node, struct vnode **target, const char *component_name);
int fat32_readdir(struct vnode *dir_node, const char name_array[]);