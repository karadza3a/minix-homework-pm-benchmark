  if (state.s_read_only)
int do_stat(void)
  struct stat stat;
  ino_t ino_nr;
  ino_nr = m_in.m_vfs_fs_stat.inode;

  memset(&stat, 0, sizeof(struct stat));

  stat.st_dev = state.s_dev;
  stat.st_ino = ino_nr;
  stat.st_mode = get_mode(ino, attr.a_mode);
  stat.st_uid = sffs_params->p_uid;
  stat.st_gid = sffs_params->p_gid;
  stat.st_rdev = NO_DEV;
  stat.st_size = attr.a_size;
  stat.st_atimespec = attr.a_atime;
  stat.st_mtimespec = attr.a_mtime;
  stat.st_ctimespec = attr.a_ctime;
  stat.st_birthtimespec = attr.a_crtime;
  stat.st_blocks = stat.st_size / S_BLKSIZE;
  if (stat.st_size % S_BLKSIZE != 0)
	stat.st_blocks += 1;
  stat.st_blksize = BLOCK_SIZE;
  stat.st_nlink = 0;
  if (ino->i_parent != NULL) stat.st_nlink++;
	stat.st_nlink++;
	if (HAS_CHILDREN(ino)) stat.st_nlink++;
  return sys_safecopyto(m_in.m_source, m_in.m_vfs_fs_stat.grant, 0,
	(vir_bytes) &stat, sizeof(stat));
int do_chmod(void)
  if (state.s_read_only)
  if ((ino = find_inode(m_in.m_vfs_fs_chmod.inode)) == NULL)
  attr.a_mode = m_in.m_vfs_fs_chmod.mode; /* no need to convert in this direction */
  m_out.m_fs_vfs_chmod.mode = get_mode(ino, attr.a_mode);
int do_utime(void)
  if (state.s_read_only)
  if ((ino = find_inode(m_in.m_vfs_fs_utime.inode)) == NULL)
  switch(m_in.m_vfs_fs_utime.acnsec) {
	m_in.m_vfs_fs_utime.acnsec = 0;
	/* cases m_in.m_vfs_fs_utime.acnsec < 0 || m_in.m_vfs_fs_utime.acnsec >= 1E9
	 * are caught by VFS to cooperate with old instances of EXT2
	 */
	attr.a_atime.tv_sec = m_in.m_vfs_fs_utime.actime;
	attr.a_atime.tv_nsec = m_in.m_vfs_fs_utime.acnsec;
  switch(m_in.m_vfs_fs_utime.modnsec) {
	m_in.m_vfs_fs_utime.modnsec = 0;
	/* cases m_in.m_vfs_fs_utime.modnsec < 0 || m_in.m_vfs_fs_utime.modnsec >= 1E9
	 * are caught by VFS to cooperate with old instances
	 */
	attr.a_mtime.tv_sec = m_in.m_vfs_fs_utime.modtime;
	attr.a_mtime.tv_nsec = m_in.m_vfs_fs_utime.modnsec;