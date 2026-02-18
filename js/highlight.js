/**
 * Search highlighting utility.
 * Wraps matching text in <mark> tags within specified containers.
 */
var SearchHighlight = (function () {
    'use strict';

    /**
     * Remove all existing <mark> highlights within a container.
     */
    function clear(container) {
        var marks = container.querySelectorAll('mark.search-highlight');
        marks.forEach(function (mark) {
            var parent = mark.parentNode;
            parent.replaceChild(document.createTextNode(mark.textContent), mark);
            parent.normalize();
        });
    }

    /**
     * Highlight all occurrences of `term` within text nodes of `container`.
     * Skips elements that should not be highlighted (script, style, input, mark, code).
     */
    function apply(container, term) {
        if (!term || term.length < 2) return;

        var lowerTerm = term.toLowerCase();

        function walkNode(node) {
            if (node.nodeType === Node.TEXT_NODE) {
                var text = node.textContent;
                var lowerText = text.toLowerCase();
                var idx = lowerText.indexOf(lowerTerm);

                if (idx === -1) return;

                var fragment = document.createDocumentFragment();
                var lastIdx = 0;

                while (idx !== -1) {
                    // Text before match
                    if (idx > lastIdx) {
                        fragment.appendChild(document.createTextNode(text.substring(lastIdx, idx)));
                    }
                    // The match
                    var mark = document.createElement('mark');
                    mark.className = 'search-highlight';
                    mark.textContent = text.substring(idx, idx + term.length);
                    fragment.appendChild(mark);

                    lastIdx = idx + term.length;
                    idx = lowerText.indexOf(lowerTerm, lastIdx);
                }

                // Remaining text
                if (lastIdx < text.length) {
                    fragment.appendChild(document.createTextNode(text.substring(lastIdx)));
                }

                node.parentNode.replaceChild(fragment, node);
            } else if (node.nodeType === Node.ELEMENT_NODE) {
                var tag = node.tagName.toLowerCase();
                // Skip elements that should not be highlighted
                if (tag === 'script' || tag === 'style' || tag === 'input' ||
                    tag === 'textarea' || tag === 'mark' || tag === 'code') {
                    return;
                }
                // Process children in reverse to avoid issues with live NodeList
                var children = Array.prototype.slice.call(node.childNodes);
                children.forEach(walkNode);
            }
        }

        walkNode(container);
    }

    return { clear: clear, apply: apply };
})();
