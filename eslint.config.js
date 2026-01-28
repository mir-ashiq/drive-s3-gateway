export default [
  {
    files: ["**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        console: "readonly",
        fetch: "readonly",
        crypto: "readonly",
        Request: "readonly",
        Response: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        Headers: "readonly",
        TextEncoder: "readonly",
        KVNamespace: "readonly",
        btoa: "readonly",
        atob: "readonly",
      },
    },
    rules: {},
  },
];
