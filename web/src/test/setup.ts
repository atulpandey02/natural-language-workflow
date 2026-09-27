import "@testing-library/jest-dom/vitest";

// jsdom has no layout engine; native responsive disclosures still need the
// browser's MediaQueryList interface. Individual responsive tests override it.
if (typeof window !== "undefined")
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (media: string) => ({
      matches: true,
      media,
      onchange: null,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      dispatchEvent: () => true,
    }),
  });
