#include "fat32.h"
#include "debug.h"
#include "vfs.h"
#include "memory.h"
#include "uart1.h"
#include "sdhost.h"

const file_operations_t fat32_file_operations = {fat32_write, fat32_read, fat32_open, fat32_close, fat32_lseek64, fat32_getsize};
const vnode_operations_t fat32_vnode_operations = {fat32_lookup, fat32_create, fat32_mkdir, fat32_readdir};
filesystem_t *fat32_fs;

static struct MBR *mbr;
static struct bpb_fat32 *bpb;
static uint64_t FAT_DATA_LBA;
static struct fs_info *fs_info;
static uint32_t *file_allocation_table;

#define sfn_entry_for_each(pos, buf) \
	for (readblock(FAT_DATA_LBA, buf), pos = (struct sfn_entry *)buf; *((uint8_t *)pos) != 0; pos++)

static inline uint32_t get_first_cluster(struct sfn_entry *entry)
{
	return (entry->first_cluster_high << 16) | entry->first_cluster_low;
}

static inline const char *get_filesystem_name(int partition_type)
{
	switch (partition_type)
	{
	case 0x01:
		return "FAT12";
	case 0x04:
	case 0x06:
	case 0x0E:
		return "FAT16";
	case 0x05:
	case 0x0F:
		return "Extended Partition";
	case 0x07:
		return "NTFS or exFAT";
	case 0x0B:
	case 0x0C:
		return "FAT32";
	case 0x82:
	case 0x83:
		return "Linux";
	case 0x8E:
		return "Linux LVM";
	case 0xA5:
	case 0xA6:
	case 0xA9:
		return "BSD";
	case 0xA8:
	case 0xAB:
	case 0xAF:
		return "Apple MacOS";
	case 0xFD:
		return "Linux RAID";
	default:
		return "Unknown or Unsupported";
	}
}

static inline uint32_t f_pos_to_num_of_cluster(size_t f_pos)
{
	return (uint32_t)(f_pos / BLOCK_SIZE);
}

/**
 * @brief Convert file position to bytes offset
 */
static inline uint32_t f_pos_to_offset_bytes(size_t f_pos)
{
	return (uint32_t)(f_pos % BLOCK_SIZE);
}

/**
 * @brief Convert file position to page offset(cluster num)
 */
static inline uint32_t f_pos_to_page_offset_cluster(size_t f_pos)
{
	return f_pos_to_num_of_cluster(f_pos) % 4;
}

static inline uint32_t get_max_cluster_num()
{
	static uint32_t max_cluster_num = 0;
	if (max_cluster_num == 0)
	{
		max_cluster_num = (bpb->fat_size_32 * bpb->bytes_per_sector / sizeof(uint32_t));
	}
	return max_cluster_num;
}

static inline uint32_t find_cluster_of_file(uint32_t first_cluster, uint32_t num_of_cluster)
{
	uint32_t next_cluster = first_cluster;
	for (int i = 0; i < num_of_cluster; i++)
	{
		if (file_allocation_table[next_cluster] == 0)
			return 0;
		DEBUG("find_cluster_of_file: 0x%x -> 0x%x\r\n", next_cluster, file_allocation_table[next_cluster]);
		next_cluster = file_allocation_table[next_cluster];
	}
}

static inline uint32_t find_free_cluster()
{
	for (int i = fs_info->next_free; i < get_max_cluster_num(); i++)
	{
		if (file_allocation_table[i] == FAT32_FREE_CLUSTER)
		{
			DEBUG("find_free_cluster: 0x%x\r\n", i);
			return i;
		}
	}
	return 0;
}

static inline void fat32_get_file_name(char *name_array, struct sfn_entry *entry)
{
	int idx = 0;
	for (int i = 0; i < FAT32_MAX_FILENAME; i++, idx++)
	{
		if (entry->name[i] == ' ')
		{
			break;
		}
		name_array[idx] = entry->name[i];
	}
	for (int i = 0; i < FAT32_MAX_EXTENSION; i++, idx++)
	{
		if (entry->extension[i] == ' ')
		{
			break;
		}
		else if (i == 0)
		{
			name_array[idx++] = '.';
		}
		name_array[idx] = entry->extension[i];
	}
	DEBUG("fat32_get_file_name: %s\r\n", name_array);
	name_array[idx] = '\0';
}

int register_fat32()
{
	sd_init();
	fat32_fs = kmalloc(sizeof(filesystem_t));
	fat32_fs->name = "fat32";
	fat32_fs->setup_mount = fat32_setup_mount;
	register_filesystem(fat32_fs);
	return 0;
}

static inline void __read_fat32()
{
	uint8_t buf[BLOCK_SIZE];
	readblock(0, &buf);
	mbr = kmalloc(sizeof(struct MBR));
	memcpy(mbr, buf, sizeof(struct MBR));
	DEBUG("mbr signature: 0x%x\r\n", mbr->signature);
	DEBUG("mbr partition_table[0].status: 0x%x\r\n", mbr->partition_table[0].status);
	DEBUG("mbr partition_table[0].type: 0x%x %s\r\n", mbr->partition_table[0].type, get_filesystem_name(mbr->partition_table[0].type));
	DEBUG("mbr partition_table[0].start_lba: 0x%x\r\n", mbr->partition_table[0].start_lba);
	DEBUG("mbr partition_table[0].size: 0x%x\r\n", mbr->partition_table[0].size);

	readblock(mbr->partition_table[0].start_lba, buf);
	bpb = kmalloc(sizeof(struct bpb_fat32));
	memcpy(bpb, buf, sizeof(struct bpb_fat32));
	DEBUG("bpb bytes_per_sector: %d\r\n", bpb->bytes_per_sector);
	DEBUG("bpb sectors_per_cluster: %d\r\n", bpb->sectors_per_cluster);
	DEBUG("bpb hidden_sectors: 0x%x\r\n", bpb->hidden_sectors);
	DEBUG("bpb reserved_sector_count: %d\r\n", bpb->reserved_sector_count);
	DEBUG("bpb fat_size_32: 0x%x\r\n", bpb->fat_size_32);
	DEBUG("bpb num_fats: %d\r\n", bpb->num_fats);
	DEBUG("bpb root_cluster: 0x%x\r\n", bpb->root_cluster);
	DEBUG("bpb total_sectors_32: 0x%x\r\n", bpb->total_sectors_32);
	DEBUG("bpb fs_info: 0x%x\r\n", bpb->fs_info);
	FAT_DATA_LBA = bpb->reserved_sector_count + bpb->hidden_sectors + bpb->fat_size_32 * bpb->num_fats;
	DEBUG("FAT_DATA_LBA: 0x%x\r\n", FAT_DATA_LBA);

	readblock(bpb->hidden_sectors + bpb->fs_info, buf);
	fs_info = kmalloc(sizeof(struct fs_info));
	memcpy(fs_info, buf, sizeof(struct fs_info));
	DEBUG("fs_info lead_signature: 0x%x\r\n", fs_info->lead_signature);
	DEBUG("fs_info structure_signature: 0x%x\r\n", fs_info->structure_signature);
	DEBUG("fs_info free_cluster_count: 0x%x\r\n", fs_info->free_count);
	DEBUG("fs_info next_free_cluster: 0x%x\r\n", fs_info->next_free);
	DEBUG("fs_info trail_signature: 0x%x\r\n", fs_info->trail_signature);

	file_allocation_table = kmalloc(get_max_cluster_num());
	DEBUG("fat size: 0x%x\r\n", get_max_cluster_num());
	for (int i = 0; i < bpb->fat_size_32; i++)
		readblock(bpb->hidden_sectors + bpb->reserved_sector_count + i, file_allocation_table + i * bpb->bytes_per_sector / sizeof(uint32_t));

	size_t f_pos = 0x5555;
	uint32_t num_of_cluster = f_pos_to_num_of_cluster(f_pos);
	uint32_t offset_bytes = f_pos_to_offset_bytes(f_pos);
	uint32_t offset_cluster = f_pos_to_page_offset_cluster(f_pos);
	uint32_t cluster = find_cluster_of_file(0xAB, num_of_cluster);
	DEBUG("f_pos: 0x%x, num_of_cluster: 0x%x, offset_bytes: 0x%x, offset_cluster: 0x%x, cluster: 0x%x\r\n", f_pos, num_of_cluster, offset_bytes, offset_cluster, cluster);
	// readblock(bpb->hidden_sectors + bpb->reserved_sector_count, file_allocation_table);
	// for (int i = 0x3; i < 0x7CB; i++)
	// 	DEBUG("file_allocation_table[0x%x]: 0x%x\r\n", i, file_allocation_table[i]);
	// DEBUG("file_allocation_table[2]: 0x%x\r\n", file_allocation_table[2]);
	// for(int i = 0; i < bpb->fat_size_32; i++)
	// 	readblock(bpb->reserved_sector_count + i, file_allocation_table + i * bpb->bytes_per_sector / sizeof(uint32_t));

	struct sfn_entry *entry;
	sfn_entry_for_each(entry, buf)
	{
		DEBUG("--------------------------------------------------------------------\r\n");
		DEBUG("entry: 0x%x\r\n", entry);
		DEBUG("entry name: %s\r\n", entry->name);
		DEBUG("entry extension: %s\r\n", entry->extension);
		DEBUG("entry attribute: 0x%x\r\n", entry->attribute);
		DEBUG("entry creation_time_tenth_seconds: 0x%x\r\n", entry->creation_time_tenth_seconds);
		DEBUG("entry creation_time: 0x%x\r\n", entry->creation_time);
		DEBUG("entry creation_date: 0x%x\r\n", entry->creation_date);
		DEBUG("entry last_access_date: 0x%x\r\n", entry->last_access_date);
		DEBUG("entry first_cluster_high: 0x%x\r\n", entry->first_cluster_high);
		DEBUG("entry last_write_time: 0x%x\r\n", entry->last_write_time);
		DEBUG("entry last_write_date: 0x%x\r\n", entry->last_write_date);
		DEBUG("entry first_cluster_low: 0x%x\r\n", entry->first_cluster_low);
		DEBUG("entry file_size: 0x%x\r\n", entry->file_size);
		uint32_t cluster = get_first_cluster(entry);
		DEBUG("entry cluster: 0x%x\r\n", cluster);
	}
	return;
}

/**
 * @brief Setup the superblock point for fat32
 *
 * @param fs
 * @param _mount
 * @param name superblock point name
 */
int fat32_setup_mount(filesystem_t *fs, mount_t *_mount, vnode_t *parent, const char *name)
{
	_mount->fs = fs;
	_mount->v_ops = &fat32_vnode_operations;
	_mount->f_ops = &fat32_file_operations;
	_mount->root = fat32_create_vnode(_mount, FS_DIR, NULL, name, NULL, 0);
	_mount->root->parent = parent;
	__read_fat32();
	return 0;
}

vnode_t *fat32_create_vnode(mount_t *superblock, enum fsnode_type type, vnode_t *parent, const char *name, uint32_t first_cluster, uint32_t filesize)
{
	vnode_t *node = create_vnode();
	node->superblock = superblock;
	node->v_ops = &fat32_vnode_operations;
	node->f_ops = &fat32_file_operations;
	node->parent = parent;
	node->mount = NULL;
	node->type = type;
	fat32_inode_t *inode = fat32_create_inode(type, name, first_cluster, filesize);
	node->internal = inode;
	node->name = inode->name;

	if (parent != NULL)
	{
		fat32_inode_t *dir_inode = (fat32_inode_t *)parent->internal;
		vnode_list_t *newvnode_list = kmalloc(sizeof(vnode_list_t));
		newvnode_list->vnode = node;
		list_add_tail((list_head_t *)newvnode_list, (list_head_t *)dir_inode->child_list);
	}
	DEBUG("node name: %s\r\n", node->name);
	DEBUG("inode name: %s\r\n", inode->name);
	return node;
}

fat32_inode_t *fat32_create_inode(enum fsnode_type type, const char *name, uint32_t first_cluster, uint32_t filesize)
{
	struct fat32_inode *inode = kmalloc(sizeof(struct fat32_inode));
	inode->data = NULL;
	inode->first_cluster = first_cluster;
	inode->filesize = filesize;
	DEBUG("fat32_create_inode: %s\r\n", name);
	strcpy(inode->name, name);
	DEBUG("fat32_create_inode: inode->name %s\r\n", inode->name);
	if (type == FS_DIR)
	{
		inode->child_list = kmalloc(sizeof(vnode_list_t));
		INIT_LIST_HEAD(&inode->child_list->list_head);
	}
	else if (type == FS_FILE)
	{
		inode->child_list = NULL;
	}
	else
	{
		ERROR("fat32_create_inode: unknown type\r\n");
		return NULL;
	}
	return inode;
}

int fat32_write(struct file *file, const void *buf, size_t len)
{
	struct fat32_inode *inode = file->vnode->internal;
	uint32_t cluster = inode->first_cluster;
	uint32_t sector = FAT_DATA_LBA + (cluster - 2) * bpb->sectors_per_cluster;
	uint8_t block[BLOCK_SIZE];
	readblock(sector, block);
	memcpy(block + file->f_pos, buf, len);
	writeblock(sector, block);
	inode->filesize = len + file->f_pos > inode->filesize ? len + file->f_pos : inode->filesize;
	return len;
}

int fat32_read(struct file *file, void *buf, size_t len)
{
	struct fat32_inode *inode = file->vnode->internal;
	uint32_t cluster = inode->first_cluster;
	uint32_t sector = FAT_DATA_LBA + (cluster - 2) * bpb->sectors_per_cluster;
	uint8_t block[BLOCK_SIZE];
	readblock(sector, block);
	len = len > inode->filesize ? inode->filesize : len;
	memcpy(buf, block, len);
	return len;
}

int fat32_open(struct vnode *file_node, struct file **target)
{
	(*target)->vnode = file_node;
	(*target)->f_ops = file_node->f_ops;
	(*target)->f_pos = 0;
	return 0;
}

int fat32_close(struct file *file)
{
	kfree(file);
	return 0;
}

long fat32_lseek64(struct file *file, long offset, int whence)
{
	if (whence == SEEK_SET)
	{
		file->f_pos = offset;
		return file->f_pos;
	}
	return -1;
}

long fat32_getsize(struct vnode *vd)
{
	struct fat32_inode *inode = vd->internal;
	return inode->filesize;
}

int fat32_lookup(struct vnode *dir_node, struct vnode **target, const char *component_name)
{
	DEBUG("fat32_lookup: %s\r\n", component_name);
	fat32_inode_t *dir_inode = (fat32_inode_t *)dir_node->internal;
	list_head_t *curr;
	vnode_t *child_vnode;
	fat32_inode_t *child_inode;
	char name[MAX_FILE_NAME];
	list_for_each(curr, (list_head_t *)(dir_inode->child_list))
	{
		child_vnode = ((vnode_list_t *)curr)->vnode;
		child_inode = (fat32_inode_t *)(child_vnode->internal);
		if (strcmp(child_vnode->name, component_name) == 0)
		{
			*target = child_vnode;
			return 0;
		}
	}
	struct sfn_entry *entry;
	uint8_t buf[BLOCK_SIZE];
	char name_array[MAX_FILE_NAME];
	DEBUG("------------------------------------\r\n");
	sfn_entry_for_each(entry, buf)
	{
		DEBUG("fat32_lookup: entry: 0x%xm, name: %s\r\n", entry, entry->name);
		fat32_get_file_name(name_array, entry);
		if (strcmp(name_array, component_name) == 0)
		{
			DEBUG("fat32_lookup: found %s\r\n", component_name);
			*target = fat32_create_vnode(dir_node->superblock, FS_FILE, dir_node, component_name, get_first_cluster(entry), entry->file_size);
			return 0;
		}
	}
	return -1;
}

int fat32_create(struct vnode *dir_node, struct vnode **target, const char *component_name)
{
	DEBUG("fat32_create: %s/%s\r\n", dir_node->name, component_name);
	struct fat32_inode *inode = dir_node->internal;

	if (dir_node->type != FS_DIR)
	{
		ERROR("fat32 create not dir_t\r\n");
		return -1;
	}

	if (strlen(component_name) > MAX_FILE_NAME)
	{
		ERROR("FILE NAME TOO LONG\r\n");
		return -1;
	}
	char blank[8] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
	uint32_t cluster = find_free_cluster();

	uint8_t buf[BLOCK_SIZE];
	struct sfn_entry *entry;
	sfn_entry_for_each(entry, buf)
	{
		if (entry->name[0] == 0xE5 || entry->name[0] == 0x00)
		{
			break;
		}
	}

	memcpy(entry->name, blank, FAT32_MAX_FILENAME);
	memcpy(entry->extension, blank, FAT32_MAX_EXTENSION);
	size_t dot_idx = -1;
	for (int i = 0; i < strlen(component_name); i++)
	{
		if (component_name[i] == '.')
		{
			dot_idx = i;
			break;
		}
	}
	if (dot_idx == -1)
	{
		strcpy(entry->name, component_name);
	}
	else
	{
		memcpy(entry->name, component_name, dot_idx);
		memcpy(entry->extension, component_name + dot_idx + 1, strlen(component_name) - dot_idx - 1);
	}
	entry->attribute = 0x20;
	entry->creation_time_tenth_seconds = 0;
	entry->creation_time = 0;
	entry->creation_date = 0;
	entry->last_access_date = 0;
	entry->first_cluster_high = (cluster & 0xFFFF0000) >> 16;
	entry->last_write_time = 0;
	entry->last_write_date = 0;
	entry->first_cluster_low = cluster & 0x0000FFFF;
	entry->file_size = 512;
	file_allocation_table[cluster] = FAT32_END_OF_CHAIN;
	vnode_t *_vnode = fat32_create_vnode(dir_node->superblock, FS_FILE, dir_node, component_name, cluster, 512);
	writeblock(FAT_DATA_LBA, buf);
	*target = _vnode;
	return 0;
}

int fat32_mkdir(struct vnode *dir_node, struct vnode **target, const char *component_name)
{
	ERROR("fat32_mkdir: not implemented\r\n");
}

int __fat32_mkdir(struct vnode *dir_node, struct vnode **target, const char *component_name)
{
}

int fat32_readdir(struct vnode *dir_node, const char name_array[])
{
	struct fat32_inode *inode = dir_node->internal;
	DEBUG("fat32_readdir: %s\r\n", dir_node->name);

	if (dir_node->type != FS_DIR)
	{
		ERROR("fat32 readdir not dir_t\r\n");
		return -1;
	}

	struct sfn_entry *entry;
	size_t max_len = 0;
	char *name_array_start = name_array;
	uint8_t buf[BLOCK_SIZE];
	sfn_entry_for_each(entry, buf)
	{
		DEBUG("fat32_readdir: entry: 0x%x\r\n", entry);
		*name_array_start = FS_FILE;
		fat32_get_file_name(++name_array_start, entry);
		name_array_start += strlen(name_array_start) + 1;
		DEBUG("fat32_readdir: child_vnode->name %s\r\n", entry->name);
	}

	return 0;
}