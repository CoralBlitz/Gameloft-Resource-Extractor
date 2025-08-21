import os
import zipfile
import flet as ft
from PIL import Image
import io
import threading
import base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import monotonic, sleep
from typing import Dict, List, Optional, Tuple

KEY_SCAN_BYTES = 512
SIGNATURES = {
    "mid": b"MThd",
    "png": b"\x89PNG",
    "jpg": b"\xFF\xD8\xFF",
    "gif": b"GIF8",
    "bmp": b"BM",
    "zip": b"PK\x03\x04",
    "wav": b"RIFF",
    "amr": b"#!AMR",
    "mp3_id3": b"ID3",
    "mp3_frame": b"\xFF\xFB",
}
TEXT_SIGNS = [b"<?xml", b"<resources", b"{", b"\""]

class LogBuffer:

    def __init__(self, tf: ft.TextField, interval_sec: float = 0.15):
        self._tf = tf
        self._interval = interval_sec
        self._buf: List[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        while not self._stop.is_set():
            sleep(self._interval)
            self.flush()

    def write(self, msg: str):
        with self._lock:
            self._buf.append(msg)

    def clear(self):
        with self._lock:
            self._tf.value = ""
            self._buf.clear()

    def flush(self):
        chunk = None
        with self._lock:
            if self._buf:
                chunk = "\n".join(self._buf) + "\n"
                self._buf.clear()
        if chunk:
            self._tf.value += chunk
            self._tf.update()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=0.5)
        self.flush()

class AudioPlayer:

    def __init__(self):
        self._current_file = None
        self._playing = False
        self._midi_player = None
        self._init_midi()

    def _init_midi(self):
        try:
            import pygame
            from pygame import mixer
            pygame.init()
            mixer.init()
            self._midi_player = mixer
            self._midi_available = True
        except ImportError:
            self._midi_available = False

    def play(self, file_path: str):
        self.stop()
        self._current_file = file_path
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.mid' and self._midi_available:
            try:
                self._midi_player.music.load(file_path)
                self._midi_player.music.play()
                self._playing = True
                return True
            except Exception as e:
                print(f"MIDI playback error: {e}")
                return False
        else:
            try:
                os.startfile(file_path) if os.name == 'nt' else os.system(f'xdg-open "{file_path}"')
                self._playing = True
                return True
            except Exception as e:
                print(f"Audio playback error: {e}")
                return False
        return False

    def stop(self):
        if self._playing and self._midi_available and self._current_file and self._current_file.endswith('.mid'):
            self._midi_player.music.stop()
        self._playing = False
        self._current_file = None

    @property
    def is_playing(self) -> bool:
        return self._playing

    @property
    def current_file(self) -> Optional[str]:
        return self._current_file


# ========== Вспомогательные функции ==========
def try_xor(data: bytes, key: int) -> bytes:
    if key == 0:
        return data
    return bytes(b ^ key for b in data)


def save_chunk(data: bytes, out_dir: str, prefix: str, ext: str, index: int) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{prefix}_{index}.{ext}")
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def is_probably_text(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    nul_ratio = data.count(0) / len(data)
    if nul_ratio > 0.3:
        try:
            _ = data.decode("utf-16")
            return True
        except Exception:
            pass
    printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in data)
    return (printable / max(1, len(data))) >= threshold


def find_xor_key(data: bytes, extra_signatures: Optional[List[bytes]] = None) -> Optional[int]:
    scan = memoryview(data)[:KEY_SCAN_BYTES]
    signatures = list(SIGNATURES.values())
    if extra_signatures:
        signatures += list(extra_signatures)

    for key in range(256):
        test = try_xor(scan.tobytes(), key)
        if any(sig in test for sig in signatures):
            return key

    for key in range(256):
        test = try_xor(scan.tobytes(), key)
        if is_probably_text(test, threshold=0.8):
            return key
    return None


def _next_sig_pos(data: bytes, start: int) -> int:
    positions = [data.find(s, start + 1) for s in SIGNATURES.values()]
    positions = [p for p in positions if p != -1]
    return min(positions) if positions else len(data)


def extract_by_signature(
    data: bytes, sig: bytes, ext: str, out_dir: str, base_name: str, xor_key: int
) -> List[str]:
    idx = 0
    count = 0
    results: List[str] = []
    sig_len = len(sig)

    while True:
        start = data.find(sig, idx)
        if start == -1:
            break

        if ext == "mid":
            next_start = data.find(sig, start + sig_len)
            chunk = data[start:next_start] if next_start != -1 else data[start:]
        elif ext == "png":
            end = data.find(b"IEND", start)
            if end == -1:
                next_sig = _next_sig_pos(data, start)
                chunk = data[start:next_sig]
            else:
                chunk = data[start : end + 8]
        elif ext == "jpg":
            end = data.find(b"\xFF\xD9", start)
            chunk = data[start : end + 2] if end != -1 else data[start:]
        elif ext == "gif":
            end = data.find(b"\x3B", start)
            chunk = data[start : end + 1] if end != -1 else data[start:]
        elif ext in ("bmp", "zip", "wav", "mp3", "mp3_id3"):
            next_sig = _next_sig_pos(data, start)
            chunk = data[start:next_sig]
        else:
            next_sig = min(_next_sig_pos(data, start), start + 4096)
            chunk = data[start:next_sig]

        out_path = save_chunk(chunk, out_dir, f"{base_name}_xor{hex(xor_key)}", ext, count)
        results.append(out_path)
        count += 1
        idx = start + sig_len

    return results


def extract_texts_from_buffer(buf: bytes, out_dir: str, base_name: str, key: int) -> List[str]:
    results: List[str] = []
    i = 0
    n = len(buf)
    chunk_index = 0

    while i < n:
        if 32 <= buf[i] <= 126 or buf[i] in (9, 10, 13):
            j = i
            while j < n and (32 <= buf[j] <= 126 or buf[j] in (9, 10, 13)):
                j += 1
            length = j - i
            if length >= 20:
                chunk = buf[i:j]
                out = save_chunk(chunk, out_dir, f"{base_name}_xor{hex(key)}", "txt", chunk_index)
                results.append(out)
                chunk_index += 1
            i = j
        else:
            i += 1

    if not results and is_probably_text(buf, threshold=0.6):
        out = save_chunk(buf, out_dir, f"{base_name}_xor{hex(key)}", "txt", 0)
        results.append(out)

    return results


# ========== Извлечение (параллельно по файлам) ==========
def _process_jar_member(
    name: str,
    data: bytes,
    output_dir: str,
    extract_midi: bool,
    extract_images: bool,
    extract_texts: bool,
) -> Tuple[Dict[str, List[str]], List[str]]:
    log_lines: List[str] = []
    extracted: Dict[str, List[str]] = {"images": [], "midi": [], "text": [], "audio": [], "others": []}

    base_name = os.path.splitext(os.path.basename(name))[0]
    key = find_xor_key(data, extra_signatures=TEXT_SIGNS)
    key = 0 if key is None else key
    buf = try_xor(data, key)

    if extract_midi and SIGNATURES["mid"] in buf:
        mids = extract_by_signature(buf, SIGNATURES["mid"], "mid", os.path.join(output_dir, "midi"), base_name, key)
        for m in mids:
            log_lines.append(f"[MIDI] {os.path.basename(m)}")
            extracted["midi"].append(m)

    if extract_images:
        for img_type, sig in [("png", SIGNATURES["png"]), ("jpg", SIGNATURES["jpg"]), ("gif", SIGNATURES["gif"]), ("bmp", SIGNATURES["bmp"])]:
            if sig in buf:
                imgs = extract_by_signature(buf, sig, img_type, os.path.join(output_dir, "images"), base_name, key)
                for img in imgs:
                    log_lines.append(f"[{img_type.upper()}] {os.path.basename(img)}")
                    extracted["images"].append(img)

    audio_types = [("mp3", SIGNATURES["mp3_id3"]), ("mp3", SIGNATURES["mp3_frame"]), ("wav", SIGNATURES["wav"]), ("amr", SIGNATURES["amr"])]
    for audio_ext, sig in audio_types:
        if sig in buf:
            audio_files = extract_by_signature(buf, sig, audio_ext, os.path.join(output_dir, "audio"), base_name, key)
            for audio in audio_files:
                log_lines.append(f"[{audio_ext.upper()}] {os.path.basename(audio)}")
                extracted["audio"].append(audio)

    if SIGNATURES["zip"] in buf:
        zips = extract_by_signature(buf, SIGNATURES["zip"], "zip", os.path.join(output_dir, "containers"), base_name, key)
        for z in zips:
            log_lines.append(f"[ZIP] {os.path.basename(z)}")
            extracted["others"].append(z)

    if extract_texts:
        texts: List[str] = []
        if is_probably_text(buf):
            texts = extract_texts_from_buffer(buf, os.path.join(output_dir, "text"), base_name, key)
        else:
            for k in range(256):
                if k == key:
                    continue
                test = try_xor(data, k)
                if is_probably_text(test):
                    t = extract_texts_from_buffer(test, os.path.join(output_dir, "text"), base_name, k)
                    if t:
                        texts.extend(t)
                        break
            for s in TEXT_SIGNS:
                if s in buf:
                    t = extract_texts_from_buffer(buf, os.path.join(output_dir, "text"), base_name, key)
                    texts.extend(t)
                    break
        for t in texts:
            log_lines.append(f"[TXT] {os.path.basename(t)}")
            extracted["text"].append(t)

    return extracted, log_lines


def extract_resources_from_jar(
    jar_path: str,
    output_dir: str,
    log_func,
    extract_midi: bool = True,
    extract_images: bool = True,
    extract_texts: bool = True,
) -> Dict[str, List[str]]:
    os.makedirs(output_dir, exist_ok=True)
    aggregated: Dict[str, List[str]] = {"images": [], "midi": [], "text": [], "audio": [], "others": []}

    try:
        with zipfile.ZipFile(jar_path, "r") as jar:
            names = jar.namelist()
            with ThreadPoolExecutor(max_workers=min(8, max(2, os.cpu_count() or 2))) as pool:
                futures = []
                for name in names:
                    try:
                        data = jar.read(name)
                    except Exception as e:
                        log_func(f"[-] Failed to read {name}: {e}")
                        continue
                    futures.append(
                        pool.submit(
                            _process_jar_member,
                            name,
                            data,
                            output_dir,
                            extract_midi,
                            extract_images,
                            extract_texts,
                        )
                    )
                total = 0
                for fut in as_completed(futures):
                    files, lines = fut.result()
                    for k, v in files.items():
                        if v:
                            aggregated[k].extend(v)
                            total += len(v)
                    for line in lines:
                        log_func(line)
                log_func(f"\n[✓] Extraction completed. Total files: {total}")
    except Exception as e:
        log_func(f"[-] Failed to open JAR: {e}")

    return aggregated


# ========== Flet GUI ==========
def main(page: ft.Page):
    page.title = "Gameloft Resource Extractor"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 16
    page.window.min_width = 900
    page.window.min_height = 875

    extracted_files: Dict[str, List[str]] = {"images": [], "midi": [], "text": [], "audio": [], "others": []}
    current_category = "images"
    current_preview_file: Optional[str] = None

    log_text = ft.TextField(
        multiline=True, 
        read_only=True, 
        expand=True, 
        border_width=0, 
        text_size=12, 
        color=ft.Colors.WHITE, 
        bgcolor=ft.Colors.BLACK12
    )
    logger = LogBuffer(log_text)

    audio_player = AudioPlayer()

    file_list = ft.ListView(expand=True)
    progress_ring = ft.ProgressRing(visible=False, width=32, height=32)

    preview_image = ft.Image(width=420, height=420, fit=ft.ImageFit.CONTAIN, visible=False)
    preview_text = ft.TextField(multiline=True, read_only=True, expand=True, visible=False, text_size=12)
    now_playing_text = ft.Text("", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN)

    preview_panel = ft.Container(
        content=ft.Column([now_playing_text, preview_image, preview_text], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center,
        expand=True,
        bgcolor=ft.Colors.BLACK12,
        border_radius=10,
        padding=10,
    )

    tabs = ft.Tabs(
        tabs=[
            ft.Tab(text="Preview", content=preview_panel),
            ft.Tab(text="Log", content=ft.Container(content=log_text, expand=True, padding=6)),
        ],
        expand=True,
    )

    def log(message: str):
        logger.write(message)
        def scroll_later():
            sleep(0.1)
            log_text.update()
        
        threading.Thread(target=scroll_later, daemon=True).start()

    def clear_log():
        logger.clear()

    def update_file_list():
        file_list.controls.clear()
        files = extracted_files.get(current_category, [])
        if not files:
            file_list.controls.append(ft.ListTile(title=ft.Text("No files found"), leading=ft.Icon(ft.Icons.INFO_OUTLINE)))
        else:
            for file_path in files:
                file_name = os.path.basename(file_path)
                file_list.controls.append(
                    ft.ListTile(
                        title=ft.Text(file_name, size=12), 
                        leading=ft.Icon(ft.Icons.FILE_OPEN), 
                        on_click=lambda e, path=file_path: preview_file(path), 
                        data=file_path
                    )
                )
        file_list.update()

    def preview_file(file_path: str):
        nonlocal current_preview_file
        current_preview_file = file_path
        preview_image.visible = False
        preview_text.visible = False
        now_playing_text.visible = False

        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp"):
            show_image_preview(file_path)
        elif ext in (".txt", ".xml", ".json", ".properties"):
            show_text_preview(file_path)
        elif ext in (".mid", ".wav", ".mp3", ".amr"):
            play_audio(file_path)
        else:
            preview_panel.content = ft.Column(
                [ft.Icon(ft.Icons.DESCRIPTION, size=40), ft.Text(f"Preview not supported for  {ext}"), ft.Text(f"Size: {os.path.getsize(file_path)} байт")],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            )
            preview_panel.update()

    def play_audio(audio_path: str):
        if audio_player.play(audio_path):
            now_playing_text.value = f"Now playing: {os.path.basename(audio_path)}"
            now_playing_text.visible = True
        else:
            now_playing_text.value = f"Failed to play: {os.path.basename(audio_path)}"
            now_playing_text.color = ft.Colors.RED
            now_playing_text.visible = True
        
        preview_panel.content = ft.Column([now_playing_text], alignment=ft.MainAxisAlignment.CENTER)
        preview_panel.update()

    def show_image_preview(image_path: str):
        try:
            img = Image.open(image_path)
            img.thumbnail((420, 420))
            img_bytes_io = io.BytesIO()
            fmt = img.format or "PNG"
            img.save(img_bytes_io, format=fmt)
            preview_image.src_base64 = base64.b64encode(img_bytes_io.getvalue()).decode("utf-8")
            preview_image.visible = True
            preview_panel.content = ft.Column([preview_image], alignment=ft.MainAxisAlignment.CENTER)
            preview_panel.update()
        except Exception as e:
            log(f"Image load error: {e}")

    def show_text_preview(text_path: str):
        try:
            with open(text_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(5000)
            preview_text.value = content
            preview_text.visible = True
            preview_panel.content = ft.Column([preview_text], alignment=ft.MainAxisAlignment.START)
            preview_panel.update()
        except Exception as e:
            log(f"Text load error: {e}")

    def select_category(category: str):
        nonlocal current_category
        current_category = category
        update_file_list()
        for btn in category_buttons:
            btn.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE if btn.data == category else None)
        for btn in category_buttons:
            btn.update()

    def extract_files(e: ft.FilePickerResultEvent):
        if not e.files:
            return
        jar_path = e.files[0].path
        output_dir = os.path.join(os.path.dirname(jar_path), "extracted_resources")

        def extract_thread():
            progress_ring.visible = True
            extract_btn.disabled = True
            progress_ring.update(); extract_btn.update()
            clear_log()
            log(f"Extracting from: {os.path.basename(jar_path)}")
            try:
                result = extract_resources_from_jar(
                    jar_path,
                    output_dir,
                    log_func=log,
                    extract_midi=midi_switch.value,
                    extract_images=images_switch.value,
                    extract_texts=texts_switch.value,
                )
                for category in extracted_files:
                    extracted_files[category] = result.get(category, [])
                for category, files in extracted_files.items():
                    if files:
                        for btn in category_buttons:
                            if btn.data == category:
                                btn.disabled = False
                                btn.update()
                for category in ["images", "text", "midi", "audio", "others"]:
                    if extracted_files.get(category):
                        select_category(category)
                        break
                log(f"\nExtraction complete! Files saved to: {output_dir}")
            except Exception as ex:
                log(f"Extraction error: {ex}")
            finally:
                progress_ring.visible = False
                extract_btn.disabled = False
                progress_ring.update(); extract_btn.update()

        threading.Thread(target=extract_thread, daemon=True).start()

    file_picker = ft.FilePicker(on_result=extract_files)
    page.overlay.append(file_picker)

    extract_btn = ft.ElevatedButton(
        "Select JAR and Extract",
        icon=ft.Icons.FILE_OPEN,
        on_click=lambda _: file_picker.pick_files(allowed_extensions=["jar"], dialog_title="Select a JAR file"),
    )

    midi_switch = ft.Switch(label="Audio", value=True)
    images_switch = ft.Switch(label="Images", value=True)
    texts_switch = ft.Switch(label="Texts", value=True)
    
    category_buttons: List[ft.ElevatedButton] = []
    for category in ["images", "text", "midi", "audio", "others"]:
        btn = ft.ElevatedButton(
            category.capitalize(), 
            data=category, 
            disabled=True, 
            on_click=lambda e, cat=category: select_category(cat)
        )
        category_buttons.append(btn)

    page.add(
        ft.Column(
            [
                ft.Row([extract_btn, progress_ring]),
                ft.Row(
                    [
                        ft.Column(
                            [
                                ft.Text("Extraction Options:", weight=ft.FontWeight.BOLD),
                                midi_switch,
                                images_switch,
                                texts_switch,
                                ft.Divider(),
                                ft.Text("Categories:", weight=ft.FontWeight.BOLD),
                                *category_buttons,
                                ft.Divider(),
                                ft.Text("Files:", weight=ft.FontWeight.BOLD),
                                ft.Container(content=file_list, height=260, border=ft.border.all(1)),
                            ],
                            width=300,
                        ),
                        ft.VerticalDivider(),
                        ft.Column([tabs], expand=True),
                    ],
                    expand=True,
                ),
            ],
            expand=True,
        )
    )

    log("Ready. Select a JAR file to extract resources.")

    def on_close(e):
        try:
            audio_player.stop()
        except Exception:
            pass
        logger.close()

    page.on_disconnect = on_close


if __name__ == "__main__":
    ft.app(target=main)