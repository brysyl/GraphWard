import "@testing-library/jest-dom";

// jsdom does not implement scrollIntoView; stub it globally so components
// that call element.scrollIntoView() don't throw in the test environment.
window.HTMLElement.prototype.scrollIntoView = jest.fn();
