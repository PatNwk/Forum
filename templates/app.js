const axios = require('axios');

const accessKey = 'ynvqKfY5XNPB_sKiU7NXugQNqLEN_neVygdt6ptH9Dk';
const photoId = 'blocs-gris-3HqSeexXYpQ';

axios.get(`https://api.unsplash.com/photos/${photoId}`, {
    headers: {
        Authorization: `Client-ID ${accessKey}`
    }
})
.then(response => {
    console.log(response.data);
})
.catch(error => {
    console.log(error);
});
