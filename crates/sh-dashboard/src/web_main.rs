//! Soul Hunter Dashboard - Dioxus Web UI
//! 
//! A modern, reactive web interface for the Soul Hunter security analysis platform.

use dioxus::prelude::*;
use dioxus_router::prelude::*;

mod components;
mod pages;
mod api;

use components::{Header, Footer, Sidebar, StatusBar};
use pages::{Home, Dashboard, Assessments, Findings, Settings, NewAssessment};

/// Application routes
#[derive(Clone, Routable, Debug, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Layout)]
    #[route("/")]
    Home {},
    #[route("/dashboard")]
    Dashboard {},
    #[route("/assessments")]
    Assessments {},
    #[route("/assessments/new")]
    NewAssessment {},
    #[route("/findings")]
    Findings {},
    #[route("/settings")]
    Settings {},
}

/// Main entry point
fn main() {
    // Initialize console logging for WASM
    wasm_logger::init(wasm_logger::Config::default());
    console_error_panic_hook::set_once();
    
    dioxus::launch(App);
}

/// Root application component
fn App() -> Element {
    rsx! {
        Router::<Route> {}
    }
}

/// Main layout with sidebar and content area
#[component]
fn Layout() -> Element {
    rsx! {
        div { class: "app-container",
            style: "display: flex; height: 100vh; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;",
            
            Sidebar {}
            
            div { class: "main-content",
                style: "flex: 1; display: flex; flex-direction: column; overflow: hidden;",
                
                Header {}
                
                div { class: "content-area",
                    style: "flex: 1; overflow-y: auto; padding: 24px; background: #f5f7fa;",
                    Outlet::<Route> {}
                }
                
                StatusBar {}
            }
        }
    }
}
