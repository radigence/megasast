import * as child_process from "child_process";

export function run(userInput: string): void {
    const result = eval(userInput);
    const fn = new Function(userInput);
    const el = document.createElement("div");
    el.innerHTML = userInput;
    child_process.exec(userInput);
    console.log(result, fn, el);
}
