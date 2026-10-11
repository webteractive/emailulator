//! Colors for the two system appearances, and the icons.

use std::borrow::Cow;

use gpui::{AssetSource, Global, Rgba, SharedString, WindowAppearance, rgb, rgba};

#[derive(Clone, Copy)]
pub struct Theme {
    pub dark: bool,
    pub window: Rgba,
    pub sidebar: Rgba,
    pub list: Rgba,
    pub reader: Rgba,
    pub border: Rgba,
    pub text: Rgba,
    pub muted: Rgba,
    pub faint: Rgba,
    pub accent: Rgba,
    pub on_accent: Rgba,
    pub hover: Rgba,
    pub selected: Rgba,
    pub selected_inactive: Rgba,
    pub field: Rgba,
    pub danger: Rgba,
    pub warning: Rgba,
    pub star: Rgba,
    pub selection: Rgba,
}

impl Global for Theme {}

impl Theme {
    pub fn for_appearance(appearance: WindowAppearance) -> Self {
        match appearance {
            WindowAppearance::Dark | WindowAppearance::VibrantDark => Self::dark(),
            WindowAppearance::Light | WindowAppearance::VibrantLight => Self::light(),
        }
    }

    fn light() -> Self {
        Self {
            dark: false,
            window: rgb(0xffffff),
            sidebar: rgb(0xf3f4f6),
            list: rgb(0xfbfbfc),
            reader: rgb(0xffffff),
            border: rgb(0xe2e4e9),
            text: rgb(0x1c1e23),
            muted: rgb(0x5f6673),
            faint: rgb(0x8d94a1),
            accent: rgb(0x2f6feb),
            on_accent: rgb(0xffffff),
            hover: rgba(0x0000000a),
            selected: rgb(0xdbe7ff),
            selected_inactive: rgb(0xe6e8ec),
            field: rgb(0xffffff),
            danger: rgb(0xc93a3a),
            warning: rgb(0x9a6200),
            star: rgb(0xe0a100),
            selection: rgba(0x2f6feb40),
        }
    }

    fn dark() -> Self {
        Self {
            dark: true,
            window: rgb(0x1b1d21),
            sidebar: rgb(0x16171a),
            list: rgb(0x1b1d21),
            reader: rgb(0x1f2126),
            border: rgb(0x2e3138),
            text: rgb(0xe7e9ee),
            muted: rgb(0xa1a7b3),
            faint: rgb(0x727987),
            accent: rgb(0x6ea1ff),
            on_accent: rgb(0x0d1117),
            hover: rgba(0xffffff0d),
            selected: rgb(0x26395e),
            selected_inactive: rgb(0x2a2d34),
            field: rgb(0x121316),
            danger: rgb(0xf07373),
            warning: rgb(0xe0b25c),
            star: rgb(0xf2c230),
            selection: rgba(0x6ea1ff55),
        }
    }
}

macro_rules! icons {
    ($($name:literal),* $(,)?) => {
        fn icon(path: &str) -> Option<&'static [u8]> {
            match path {
                $(concat!("icons/", $name, ".svg") => {
                    Some(include_bytes!(concat!("../../assets/icons/", $name, ".svg")))
                })*
                _ => None,
            }
        }
    };
}

icons!(
    "at",
    "check",
    "download",
    "external",
    "inbox",
    "paperclip",
    "search",
    "star",
    "star-filled",
    "trash",
    "unread",
);

/// The icons, compiled into the binary.
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        Ok(icon(path).map(Cow::Borrowed))
    }

    fn list(&self, _path: &str) -> anyhow::Result<Vec<SharedString>> {
        Ok(Vec::new())
    }
}
