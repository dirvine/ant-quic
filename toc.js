// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="introduction.html">Introduction</a></li><li class="chapter-item expanded affix "><li class="part-title">User Guide</li><li class="chapter-item expanded "><a href="getting-started.html"><strong aria-hidden="true">1.</strong> Getting Started</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="installation.html"><strong aria-hidden="true">1.1.</strong> Installation</a></li><li class="chapter-item expanded "><a href="quick-start.html"><strong aria-hidden="true">1.2.</strong> Quick Start</a></li></ol></li><li class="chapter-item expanded "><a href="configuration.html"><strong aria-hidden="true">2.</strong> Configuration</a></li><li class="chapter-item expanded "><a href="examples.html"><strong aria-hidden="true">3.</strong> Examples</a></li><li class="chapter-item expanded affix "><li class="part-title">Developer Guide</li><li class="chapter-item expanded "><a href="architecture.html"><strong aria-hidden="true">4.</strong> Architecture</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="core-components.html"><strong aria-hidden="true">4.1.</strong> Core Components</a></li><li class="chapter-item expanded "><a href="nat-traversal.html"><strong aria-hidden="true">4.2.</strong> NAT Traversal</a></li><li class="chapter-item expanded "><a href="protocol-extensions.html"><strong aria-hidden="true">4.3.</strong> Protocol Extensions</a></li></ol></li><li class="chapter-item expanded "><a href="api-reference.html"><strong aria-hidden="true">5.</strong> API Reference</a></li><li class="chapter-item expanded "><a href="testing.html"><strong aria-hidden="true">6.</strong> Testing</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="testing-unit.html"><strong aria-hidden="true">6.1.</strong> Unit Tests</a></li><li class="chapter-item expanded "><a href="testing-integration.html"><strong aria-hidden="true">6.2.</strong> Integration Tests</a></li><li class="chapter-item expanded "><a href="testing-property.html"><strong aria-hidden="true">6.3.</strong> Property Tests</a></li></ol></li><li class="chapter-item expanded "><li class="part-title">Advanced Topics</li><li class="chapter-item expanded "><a href="performance.html"><strong aria-hidden="true">7.</strong> Performance Tuning</a></li><li class="chapter-item expanded "><a href="security.html"><strong aria-hidden="true">8.</strong> Security</a></li><li class="chapter-item expanded "><a href="platform-support.html"><strong aria-hidden="true">9.</strong> Platform Support</a></li><li class="chapter-item expanded "><a href="troubleshooting.html"><strong aria-hidden="true">10.</strong> Troubleshooting</a></li><li class="chapter-item expanded affix "><li class="part-title">Reference</li><li class="chapter-item expanded "><a href="config-reference.html"><strong aria-hidden="true">11.</strong> Configuration Options</a></li><li class="chapter-item expanded "><a href="protocol-spec.html"><strong aria-hidden="true">12.</strong> Protocol Specification</a></li><li class="chapter-item expanded "><a href="glossary.html"><strong aria-hidden="true">13.</strong> Glossary</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
