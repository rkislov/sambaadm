"""Restore part of an owned snapshot, using descriptor-relative operations."""
import contextlib
import heapq

RESTORE_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
RESTORE_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
RESTORE_MAX = 2000
BROWSE_PAGE = 100


def restore_parts(path):
    if not path:
        return ()
    if not isinstance(path, str) or len(path.encode()) > 2048 or '\\' in path or any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise RuntimeError('Недопустимый путь')
    parts = tuple(path.split('/'))
    if len(parts) > 48 or any(part in ('', '.', '..') or part.lower() == '.zfs' or len(part.encode()) > 255 for part in parts):
        raise RuntimeError('Недопустимый путь')
    return parts


@contextlib.contextmanager
def restore_roots(value):
    _, manifest = read_cluster(value)
    dataset = owned_snapshot_dataset(value, manifest)
    snapshot = value['snapshot']
    if not SNAPSHOT_TAG.fullmatch(snapshot):
        raise RuntimeError('Неверное имя снимка')
    guid = run(['zfs', 'get', '-H', '-o', 'value', 'guid', dataset + '@' + snapshot]).strip()
    with contextlib.ExitStack() as stack:
        live = os.open('/srv/samba-ha/' + value['name'] + '/data', RESTORE_DIR)
        stack.callback(os.close, live)
        source = os.open('.zfs/snapshot/' + snapshot, RESTORE_DIR, dir_fd=live)
        stack.callback(os.close, source)
        yield live, source, guid


def restore_stamp(info):
    if info is None:
        return None
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def restore_kind(info):
    if info is None:
        return None
    if stat.S_ISDIR(info.st_mode):
        return 'directory'
    if stat.S_ISREG(info.st_mode):
        return 'file'
    return 'unsupported'


def restore_stat(parent, name, device):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if info.st_dev != device:
        raise RuntimeError('Путь пересекает границу файловой системы')
    return info


@contextlib.contextmanager
def restore_dir(root, parts, expected=None):
    with contextlib.ExitStack() as stack:
        directory = root
        device = os.fstat(root).st_dev
        for index, part in enumerate(parts):
            directory = os.open(part, RESTORE_DIR, dir_fd=directory)
            stack.callback(os.close, directory)
            info = os.fstat(directory)
            if info.st_dev != device:
                raise RuntimeError('Путь пересекает границу файловой системы')
            if expected is not None and expected.get(parts[:index+1]) != (info.st_dev,info.st_ino):
                raise RuntimeError('Папка заменена во время восстановления: '+'/'.join(parts[:index+1]))
        yield directory


def cluster_restore_browse(value, _save):
    parts = restore_parts(value['path'])
    offset = value.get('offset', 0)
    with restore_roots(value) as (_, source, _):
        with restore_dir(source, parts) as directory:
            with os.scandir(directory) as entries:
                names = heapq.nsmallest(offset+BROWSE_PAGE+1,
                    (entry.name for entry in entries if entry.name.lower() != '.zfs'))
            rows = []
            for name in names[offset:offset+BROWSE_PAGE]:
                try:
                    info=os.stat(name,dir_fd=directory,follow_symlinks=False)
                except FileNotFoundError:
                    continue
                kind = restore_kind(info) if info.st_dev == os.fstat(source).st_dev else 'unsupported'
                try:
                    restore_parts('/'.join((*parts,name)))
                except (RuntimeError,UnicodeError):
                    kind = 'unsupported'
                    name = name.encode('utf-8', 'replace').decode('utf-8')
                rows.append({'name':name,'kind':kind,'size':info.st_size})
    return {'path':'/'.join(parts),'entries':rows,
            'nextOffset':offset+BROWSE_PAGE if offset+BROWSE_PAGE<len(names) else None}


def restore_plan(live, source, parts, overwrite, guid):
    if not parts:
        raise RuntimeError('Выберите отдельный файл или папку')
    rows = []
    srcdev, dstdev = os.fstat(source).st_dev, os.fstat(live).st_dev

    def visit(path, src, dst, ancestor=False):
        if len(rows)>=RESTORE_MAX:
            raise RuntimeError('В выборе больше 2000 объектов. Восстанавливайте папку частями.')
        src_kind, dst_kind = restore_kind(src), restore_kind(dst)
        if src is None:
            raise RuntimeError('Выбранного пути нет в снимке')
        if src_kind=='unsupported' or dst_kind=='unsupported' or (dst_kind and src_kind!=dst_kind):
            action='blocked'
        elif dst is None:
            action='create'
        elif ancestor:
            action='keep'
        elif src_kind=='directory':
            action='merge' if overwrite else 'keep'
        else:
            action='replace' if overwrite else 'skip'
        rows.append({'path':'/'.join(path),'kind':src_kind,'action':action,
                     'size':src.st_size if src_kind=='file' else 0,
                     '_source':restore_stamp(src),'_target':restore_stamp(dst)})
        return src_kind=='directory' and action!='blocked'

    def tree(path, sparent, dparent, name):
        src=restore_stat(sparent,name,srcdev)
        dst=restore_stat(dparent,name,dstdev) if dparent is not None else None
        if not visit(path,src,dst):
            return
        with restore_dir(sparent,(name,)) as sdir, contextlib.ExitStack() as stack:
            ddir=stack.enter_context(restore_dir(dparent,(name,))) if dst is not None else None
            with os.scandir(sdir) as entries:
                names=[]
                for entry in entries:
                    restore_parts('/'.join((*path,entry.name)))
                    names.append(entry.name)
                    if len(names)>RESTORE_MAX-len(rows):
                        raise RuntimeError('В выборе больше 2000 объектов. Восстанавливайте папку частями.')
            for child in sorted(names):
                tree((*path,child),sdir,ddir,child)

    with contextlib.ExitStack() as stack:
        sp, dp = source, live
        for index, name in enumerate(parts[:-1]):
            if dp is not None:
                dst = restore_stat(dp,name,dstdev)
                src = restore_stat(sp,name,srcdev)
            else:
                dst = None
                src = restore_stat(sp,name,srcdev)
            if not visit(parts[:index+1],src,dst,ancestor=True):
                break
            sp = stack.enter_context(restore_dir(sp,(name,)))
            dp = stack.enter_context(restore_dir(dp,(name,))) if dst is not None else None
        else:
            tree(parts,sp,dp,parts[-1])

    # ZFS can assign a new device number after an idle snapshot automount
    # expires. The snapshot GUID, not the ephemeral mount number, pins it.
    signature=[{**row,'_source':row['_source'][1:]} for row in rows]
    fingerprint=hashlib.sha256(json.dumps([guid,overwrite,signature],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
    return rows,fingerprint


def cluster_restore_preview(value, _save):
    with restore_roots(value) as (live,source,guid):
        rows,revision = restore_plan(live,source,restore_parts(value['path']),value.get('overwrite',False),guid)
    counts={action:sum(row['action']==action for row in rows)
            for action in ('create','replace','merge','skip','keep','blocked')}
    result={'revision':revision,'counts':counts,
            'items':[{key:val for key,val in row.items() if not key.startswith('_')} for row in rows],
            'canApply':not counts['blocked'] and any(counts[key] for key in ('create','replace','merge'))}
    if len(json.dumps(result,ensure_ascii=False).encode())>900000:
        raise RuntimeError('Предпросмотр слишком большой. Восстанавливайте папку частями.')
    return result


def restore_metadata(source, target):
    info=os.fstat(source)
    attributes={key:os.getxattr(source,key) for key in os.listxattr(source)}
    os.fchown(target,info.st_uid,info.st_gid)
    os.fchmod(target,stat.S_IMODE(info.st_mode))
    for key in os.listxattr(target):
        if key not in attributes:
            os.removexattr(target,key)
    for key,value in attributes.items():
        os.setxattr(target,key,value)
    os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
    os.fsync(target)


def restore_file(sparent,dparent,name,row,device):
    with contextlib.ExitStack() as stack:
        source=os.open(name,RESTORE_FILE,dir_fd=sparent)
        stack.callback(os.close,source)
        if restore_stamp(os.fstat(source))!=row['_source']:
            raise RuntimeError('Файл в снимке изменился: '+row['path'])
        temporary='.sambaadm-restore-'+secrets.token_hex(12)
        target=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=dparent)
        stack.callback(os.close,target)
        try:
            with os.fdopen(os.dup(source),'rb') as reader,os.fdopen(os.dup(target),'wb') as writer:
                shutil.copyfileobj(reader,writer,1024*1024)
            restore_metadata(source,target)
            if restore_stamp(restore_stat(dparent,name,device))!=row['_target']:
                raise RuntimeError('Файл изменился после предпросмотра: '+row['path'])
            if row['action']=='create':
                os.link(temporary,name,src_dir_fd=dparent,dst_dir_fd=dparent,follow_symlinks=False)
            else:
                os.replace(temporary,name,src_dir_fd=dparent,dst_dir_fd=dparent)
            os.fsync(dparent)
        finally:
            try:
                os.unlink(temporary,dir_fd=dparent)
            except FileNotFoundError:
                pass


def cluster_restore_apply(value, save):
    if not value.get('confirm'):
        raise RuntimeError('Подтвердите восстановление')
    with restore_roots(value) as (live,source,guid):
        rows,revision=restore_plan(live,source,restore_parts(value['path']),value.get('overwrite',False),guid)
        if revision!=value.get('planRevision'):
            raise RuntimeError('Данные изменились. Сформируйте новый предпросмотр.')
        if any(row['action']=='blocked' for row in rows):
            raise RuntimeError('В выбранном дереве есть несовместимые объекты')
        # Remember directory identities so a directory swapped out by a client
        # cannot become the recipient of metadata from its predecessor.
        dirs=[]
        expected_dirs={
            restore_parts(row['path']):tuple(row['_target'][:2]) for row in rows
            if row['kind']=='directory' and row['_target'] is not None
        }
        files=0
        save('Восстановление файлов с их ACL и владельцами','restore')
        try:
            for row in rows:
                action=row['action']
                if action not in ('create','replace','merge'):
                    continue
                parts=restore_parts(row['path'])
                name=parts[-1]
                with restore_dir(source,parts[:-1]) as sparent,restore_dir(live,parts[:-1],expected_dirs) as dparent:
                    if row['kind']=='file':
                        restore_file(sparent,dparent,name,row,os.fstat(live).st_dev)
                        files+=1
                        if files%100==0:
                            save('Восстановлено файлов: '+str(files),'restore')
                    else:
                        if action=='create':
                            os.mkdir(name,0o700,dir_fd=dparent)
                            os.fsync(dparent)
                        with restore_dir(dparent,(name,)) as target:
                            info=os.fstat(target)
                            if action=='merge' and restore_stamp(info)!=row['_target']:
                                raise RuntimeError('Папка изменилась после предпросмотра: '+row['path'])
                            dirs.append((parts,info.st_dev,info.st_ino))
                            expected_dirs[parts]=(info.st_dev,info.st_ino)
        finally:
            # Apply parent metadata after children. Also finalize directories
            # already created if a later file could not be restored.
            for parts,device,inode in reversed(dirs):
                with restore_dir(source,parts) as sdir,restore_dir(live,parts,expected_dirs) as ddir:
                    info=os.fstat(ddir)
                    if (info.st_dev,info.st_ino)!=(device,inode):
                        raise RuntimeError('Папка заменена во время восстановления: '+'/'.join(parts))
                    restore_metadata(sdir,ddir)
            save('Записано файлов: '+str(files),'restore')
    return {'files':files,'directories':len(dirs),'path':value['path']}
