import multer, { diskStorage } from 'multer';
const storage = diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname); 
    }
});
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/avif', 'image/jpeg', 'image/png', 'image/webp','image/jpg'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true); 
    } else {
        cb(new Error('Invalid file type. Only AVIF, JPEG, PNG, and WEBP are allowed!'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
});

export default upload;