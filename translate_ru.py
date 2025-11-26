import os
import re
import time
from deep_translator import GoogleTranslator

# --- 配置 ---
# 源语言自动检测，目标语言英文
translator = GoogleTranslator(source='auto', target='en')
SLEEP_TIME = 0.5 

def do_translate(text):
    if not text or not text.strip():
        return text
    # 排除纯符号、数字、IP地址、路径
    if re.match(r'^[\W\d]+$', text) or '/opt/' in text or '192.168.' in text:
        return text
    
    try:
        res = translator.translate(text)
        time.sleep(SLEEP_TIME)
        # 日志仅打印前30个字符，保持整洁
        print(f"    [Trans] {text[:30]}... -> {res[:30]}...")
        return res
    except Exception as e:
        print(f"    [Error] {e}")
        return text

def read_file_content(file_path):
    """尝试多种编码读取，Keenetic脚本常用 cp1251 或 utf-8"""
    encodings = ['utf-8', 'windows-1251', 'cp1251', 'latin1']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                content = f.readlines()
            print(f"Opened {file_path} with encoding: {enc}")
            return content, enc
        except UnicodeDecodeError:
            continue
    print(f"[Fail] Could not read {file_path} (unknown encoding)")
    return None, None

def has_cyrillic(text):
    """检查是否包含俄语字母"""
    return bool(re.search(r'[а-яА-Я]', text))

def process_code_file(file_path):
    print(f"Processing File: {file_path}")
    lines, encoding = read_file_content(file_path)
    if not lines:
        return

    new_lines = []
    modified = False

    # 1. 匹配所有双引号或单引号内的内容 (不局限于 echo)
    # 捕获组: (前缀引号)(内容)(后缀引号)
    # 排除掉像 "$VAR" 这种纯变量引用，避免破坏代码
    string_pattern = re.compile(r'(["\'])(.*?)(["\'])')
    
    # 2. 匹配注释 (# 及其后的内容)
    comment_pattern = re.compile(r'^(.*?)(#\s+)(.*)$')

    for line in lines:
        # 跳过 Shebang
        if line.strip().startswith("#!"):
            new_lines.append(line)
            continue

        original_line = line
        
        # --- A. 处理注释 ---
        match_comment = comment_pattern.match(line)
        if match_comment:
            pre, hash_mark, content = match_comment.groups()
            # 只有当注释包含俄语时才翻译
            if has_cyrillic(content):
                trans_content = do_translate(content)
                line = f"{pre}{hash_mark}{trans_content}\n"
                modified = True
        
        # --- B. 处理字符串 (变量赋值或 echo) ---
        # 如果行内已经被注释处理过，用新的 line 继续处理字符串
        def replace_str(match):
            quote_open, content, quote_close = match.groups()
            # 1. 必须包含俄语
            # 2. 不能包含太复杂的命令替换 (如 `cmd`)，防止坏掉
            if has_cyrillic(content) and '`' not in content:
                nonlocal modified
                modified = True
                return f"{quote_open}{do_translate(content)}{quote_close}"
            return match.group(0)

        line = string_pattern.sub(replace_str, line)
        
        new_lines.append(line)

    if modified:
        print(f"  -> Saving changes to {file_path}")
        with open(file_path, 'w', encoding=encoding) as f:
            f.writelines(new_lines)
    else:
        print(f"  -> No Russian content translated in {file_path}")

def process_md_file(file_path):
    print(f"Processing MD: {file_path}")
    lines, encoding = read_file_content(file_path)
    if not lines: return

    new_lines = []
    in_code_block = False
    modified = False
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('```'):
            in_code_block = not in_code_block
            new_lines.append(line)
            continue
        
        if in_code_block or not stripped or stripped.startswith('<'):
            new_lines.append(line)
            continue
            
        # Markdown 只要包含俄语就翻译
        if has_cyrillic(line):
            prefix_match = re.match(r'^(\s*(?:#+|\-|\*|\d+\.|>)\s+)?(.*)', line)
            if prefix_match:
                prefix, content = prefix_match.groups()
                if prefix is None: prefix = ""
                translated = do_translate(content)
                new_lines.append(f"{prefix}{translated}\n")
                modified = True
                continue

        new_lines.append(line)

    if modified:
        with open(file_path, 'w', encoding=encoding) as f:
            f.writelines(new_lines)

def main():
    exclude_dirs = ['.git', '.github']
    
    # --- 关键修改：在这里添加 'config' 这种无后缀文件 ---
    target_files = ['config', 'Makefile', 'xkeen', 'OffLine_install', 'FileDescriptors', 'podkop.po', 'podkop.ru.po'] 
    target_exts = ['.sh', '.cfg', '.conf', '.list', '.lst', '.md'] 

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            
            # 判断逻辑：是指定后缀 OR 是指定文件名
            is_target_code = any(file.endswith(ext) for ext in target_exts) or (file in target_files)
            
            if is_target_code:
                process_code_file(file_path)
            elif file.lower() == "readme.md":
                process_md_file(file_path)

if __name__ == "__main__":
    main()
