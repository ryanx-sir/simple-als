import wdals from "./index.js";

wdals('http://127.0.0.1:20000').then(res => {
    console.debug(res)
}, err => {
    console.error(err)
})
