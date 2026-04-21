//! Sidebar Navigation Component

use dioxus::prelude::*;
use dioxus_router::prelude::*;

use crate::Route;

#[component]
pub fn Sidebar() -> Element {
    rsx! {
        aside { class: "sidebar",
            style: "width: 260px; background: #1a1a2e; color: white; display: flex; flex-direction: column;",
            
            // Logo
            div { class: "logo",
                style: "padding: 24px; border-bottom: 1px solid #2a2a4e;",
                h1 { style: "margin: 0; font-size: 24px; font-weight: 700; color: #00d4aa;",
                    "Soul Hunter"
                }
                p { style: "margin: 4px 0 0 0; font-size: 12px; color: #888;",
                    "Security Analysis Platform"
                }
            }
            
            // Navigation
            nav { class: "nav",
                style: "flex: 1; padding: 16px 0;",
                
                NavItem { route: Route::Home {}, icon: "🏠", label: "Home" }
                NavItem { route: Route::Dashboard {}, icon: "📊", label: "Dashboard" }
                NavItem { route: Route::Assessments {}, icon: "🔍", label: "Assessments" }
                NavItem { route: Route::Findings {}, icon: "⚠️", label: "Findings" }
                NavItem { route: Route::Settings {}, icon: "⚙️", label: "Settings" }
            }
            
            // Version
            div { class: "version",
                style: "padding: 16px 24px; border-top: 1px solid #2a2a4e; font-size: 12px; color: #666;",
                "Version 0.1.0"
            }
        }
    }
}

#[component]
fn NavItem(route: Route, icon: &'static str, label: &'static str) -> Element {
    let current_route = use_route::<Route>();
    let is_active = current_route == route;
    
    let bg_color = if is_active { "#00d4aa" } else { "transparent" };
    let text_color = if is_active { "#1a1a2e" } else { "#fff" };
    
    rsx! {
        Link {
            to: route,
            style: "display: flex; align-items: center; padding: 12px 24px; margin: 4px 16px; border-radius: 8px; text-decoration: none; background: {bg_color}; color: {text_color}; transition: all 0.2s;",
            span { style: "margin-right: 12px; font-size: 20px;", "{icon}" }
            span { style: "font-size: 14px; font-weight: 500;", "{label}" }
        }
    }
}
