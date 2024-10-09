# js-dynamic-url-finder
A Burp Suite extension that detects dynamic URLs constructed in JavaScript using `window.location.href`.

## Features
- Scans HTTP responses for JavaScript content.
- Identifies dynamic URL assignments in `window.location.href`.
- Reports findings as scan issues in Burp Suite.

## Installation

1. Download the latest python file from the [releases](https://github.com/kayodeoladeinde/js-dynamic-url-finder/releases) page.
2. Open Burp Suite and go to the Extensions tab.
3. Click on "Add" and select "python" as the extension type.
4. Choose the downloaded python file and click "Next."

## Usage

Once installed, the extension will automatically analyze HTTP responses. If it detects dynamic URL assignments in JavaScript, it will report them as scan issues in Burp Suite.

## Contributing

Feel free to submit issues or pull requests. Contributions are welcome!

## License

This project is licensed under the MIT License.
