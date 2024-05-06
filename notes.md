## Questions
* Should `readahead()` be instrumented?
* Can we get a file descriptor's flags outside of `open()`?  And which flags affect how we record our data?
  * There are `*SYNC` flags that affect how we record our data.
* Can we get everything we need about a file descriptor via `struct task_struct` and `bpf_get_current_task()`?
  * Yep...
    * Path:
      * task_struct->files (struct files_struct)
      * files_struct->fd_array (struct file)
      * struct file->path (struct path)
      * struct path->dentry (struct dentry)
      * struct dentry
        * d_name (struct qstr a.k.a. quick string)
        * parent (struct dentry)
    * Mount namespace
      * task_struct->nsproxy (struct ns_proxy)
      * struct ns_proxy->mnt_ns (struct mount_namespace)
      * struct mnt_namespace->ns (strct ns_common)
      * struct ns_common->inum (namespace ID that shows up in /proc)
    * Flags struct file->f_flags
* How can we tell from `struct file` what is a regular file, and what is a special file?
  * There is a `special_file()` macro in fs.h that takes `inode->i_mode` as an argument
  * Even better: there is a `S_ISREG()` macro in `include/linux/uapi/stat.h`
  * struct file->f_inode (struct inode)
## On socket creation:
* `sock_alloc_file()` creates the actual file struct 

## SQLite
* Discussion of SQLite performance and limitations: https://stackoverflow.com/questions/784173/what-are-the-performance-characteristics-of-sqlite-with-very-large-database-file
  (Way more to learn there)