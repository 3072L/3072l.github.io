从零开始写Fuzzer(1):实现一个dumb Fuzzer

### 1 分析win32calc.exe

![](../rustdumbpng/1.jpg)

这次的分析对象是win32calc，作为一个dumb fuzzer，我们要实现的仅仅是枚举计算器的各种操作，并期待它crash，不需要code coverage也不需要优化mutator。crash我们可以通过设置windbg为默认调试器来捕获

#### 1.1 熟悉win32calc.exe的功能

这里带大家来熟悉一下win32calc的功能

![](../rustdumbpng/1.5.jpg)

常见的计算功能

![](../rustdumbpng/2.jpg)

**Alt+V**快捷键可以打开**查看**这个菜单，在此状态下**Alt**加上数字1,2,3,4可以切换到不同的模式，同时**Ctrl**加上F4,U,E会为计算器添加额外的功能

![](../rustdumbpng/3.jpg)

**Alt+3**进入程序员模式

![](../rustdumbpng/4.jpg)

**Ctrl+E**计算日期差

![](../rustdumbpng/5.jpg)

**Ctrl+U**单位换算

![](../rustdumbpng/6.jpg)

**Ctrl+H**  *历史记录*

#### 1.2 实现思路
一个朴素的想法就是在聚焦于win32calc的情况下给窗口发送键盘事件，这其中会有很多事件并没有实际的意义，我们可以通过黑名单来减少这些噪声

### 2 代码实现

首先我们通过FindWindowW拿到窗口的句柄
```rust
struct Window{
    hwnd : isize,
    seed : Cell<u64>,
}

impl Window{
    fn attach(title: &str) -> Result<Self, Error>{
        let ret = unsafe{
            FindWindowW(None, title) 
        };
    ...


 'reconnect: loop{
        let window = Window::attach(&args[1]);
        if window.is_err() {
            println!("Couldn't attach to window");
            continue
        }
    ...
```

之后SetForegroundWindow,并生成随机的信号，其中有些是Ctrl操作有些是Alt操作，还有些常规的按键操作
```rust
if unsafe { SetForegroundWindow(window.hwnd) } == false {
                println!("Couldn't set foreground");

                continue 'reconnect;
}
    ...

let key = window.rand() as u8;
if black_list.contains(&key) {
    continue;
}

let sel = window.rand() % 3;
match sel {
    0 => { window.alt_press(key as _); }
    1 => { window.ctrl_press(key as _); }
    _ => { window.press(key as _); }
}
```

按键操作实现如下
```rust
 fn rand(&self) ->usize{
        let mut seed = self.seed.get();
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        self.seed.set(seed);
        seed as usize
    }

    fn key_down(&self, key: u8){ 
        unsafe{
            keybd_event(key, 0, 0, 0);
        }
    }

    fn key_up(&self, key: u8){
        unsafe{
            keybd_event(key, 0, KEYEVENTF_KEYUP, 0);
        }
    }

    fn alt_press(&self, key: u8) {
        if key == KeyCode::Tab as _ || 
        key == KeyCode::Space as _ || 
        key == KeyCode::Esc as _ ||
        key == KeyCode::Shift as _ {
            return;
        }
        self.key_down(KeyCode::Alt as u8);
        self.key_down(key);
        self.key_up(key);
        self.key_up(KeyCode::Alt as u8);
    }

    fn ctrl_press(&self, key: u8) {
        if key == KeyCode::Esc as _ ||
        key == KeyCode::Space as _ ||
        key == KeyCode::Shift as _ {
            return;
        }
        self.key_down(KeyCode::Ctrl as u8);
        self.key_down(key);
        self.key_up(key);
        self.key_up(KeyCode::Ctrl as u8);
    }

    fn press(&self, key: u8){
        self.key_down(key);
        self.key_up(key);
    }

    ...
```

通过黑名单来减少无效的信号

```rust
let mut black_list = HashSet::new();
    black_list.insert(0x5b); // left windows key
    black_list.insert(0x5c); // right windows key
    black_list.insert(0x5d); // Application key
    black_list.insert(0x5f); // Sleep key
    black_list.insert(0x70); // F1
    black_list.insert(0x73); // F4
    black_list.insert(0x2f); // Help key
    black_list.insert(0x2c); // Print screen
    black_list.insert(0x2a); // Print
    black_list.insert(0x2b); // Execute
    black_list.insert(0x12); // Alt
    black_list.insert(0x11); // Control
    black_list.insert(0x1b); // Escape

```

至此我们就实现了一个dumb fuzzer，来看看效果

![](../rustdumbpng/7.gif)

### 3 结果
很遗憾，经过了一晚上的fuzz，这个dumb fuzzer一个crash都没产生，真是有点dumb了:-(

不过没关系，之后我们将在这个fuzzer的基础上优化我们的输入，去掉多余的噪音，让我们产生的输入更加高效。我们还要收集code coverage,利用code coverage去评估和优化我们的mutation。另外我们还要添加多线程来并发的fuzz，从而让我们的fuzzer在20秒内就能挖到win32calc的crash

### 4 下一篇

从零开始写Fuzzer(2):实现一个smart Fuzzer


### 5 下下一篇

从零开始写Fuzzer(3):实现一个snapshot Fuzzer