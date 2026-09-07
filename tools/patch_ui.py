import io
p = r'D:\TwinStar\app\TwimStar\src\main.rs'
src = io.open(p, encoding='utf-8').read()

a = "    ctx.style_mut(|style| {\n"
assert a in src, 'style_mut open not found'
src = src.replace(a, "    let mut style = (*ctx.style()).clone();\n    {\n", 1)

b = "    });\n}\n\nfn card"
assert b in src, 'style_mut close not found'
src = src.replace(b, "    };\n    ctx.set_style(style);\n}\n\nfn card", 1)

c = """if let Some(f) = dropped.iter().find(|f| f.path().is_some()) {
            if let Some(p) = f.path() {
                self.file_path = p.display().to_string();
            }
        }"""
assert c in src, 'drop block not found'
src = src.replace(c, """if let Some(f) = dropped.first() {
            let p = f.path();
            if !p.as_os_str().is_empty() {
                self.file_path = p.display().to_string();
            }
        }""", 1)

io.open(p, 'w', encoding='utf-8').write(src)
print('PATCHED')
