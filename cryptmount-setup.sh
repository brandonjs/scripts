#!/usr/bin/env bash
set -x

CRYPTMOUNT_FILESYSTEM_NAME=ip
FILESYSTEM=ext4
FILESYSTEM_IMAGE_PATH=/local/mnt/workspace/ip.img
FILESYSTEM_MOUNT_POINT_PATH=/local/mnt/workspace/ip
FILESYSTEM_SIZE_GIGABYTES=49
KEY_FILE_PATH=/etc/cryptmount/ip.key
HOME_DIR_GROUP=users

sudo apt-get install cryptmount

mkdir -p "${FILESYSTEM_MOUNT_POINT_PATH}"
dd if=/dev/zero of="${FILESYSTEM_IMAGE_PATH}" bs=1G seek=${FILESYSTEM_SIZE_GIGABYTES} count=1

sudo tee --append /etc/cryptmount/cmtab << CMTAB_END
${CRYPTMOUNT_FILESYSTEM_NAME} {
  dev=${FILESYSTEM_IMAGE_PATH}
  dir=${FILESYSTEM_MOUNT_POINT_PATH}
  fstype=${FILESYSTEM}
  keyfile=${KEY_FILE_PATH}
}
CMTAB_END

sudo cryptmount --generate-key 32 ${CRYPTMOUNT_FILESYSTEM_NAME}

sudo cryptmount --prepar ${CRYPTMOUNT_FILESYSTEM_NAME}
sudo /sbin/mkfs.ext4 /dev/mapper/"${CRYPTMOUNT_FILESYSTEM_NAME}"
sudo cryptmount --release ${CRYPTMOUNT_FILESYSTEM_NAME}

if [ "$1" ]
then
  cryptmount -m ${CRYPTMOUNT_FILESYSTEM_NAME}
  sudo mkdir "${FILESYSTEM_MOUNT_POINT_PATH}/$1"
  sudo chown $1:${HOME_DIR_GROUP} "${FILESYSTEM_MOUNT_POINT_PATH}/$1"
  cryptmount -u ${CRYPTMOUNT_FILESYSTEM_NAME}
fi

