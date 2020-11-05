import mongoose from 'mongoose';
const productSchema = mongoose.Schema({
	_id: { type: mongoose.Schema.Types.ObjectId, required: true },
	username: { type: String, required: true },
	email: { type: String, required: true },
	password: { type: String, required: true },
});

const UserModel = mongoose.model('Users', productSchema);
export default UserModel;