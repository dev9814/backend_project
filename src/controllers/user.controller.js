import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessandRefreshTokens = async(userId)=>{
    try{
        const user = await User.find(userId);

        const accessToken =  user.generateAccessToken();
        const refreshToken =  user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}

    }
    catch(error){
        throw new ApiError(500, "Something went wrong while generating access token")
    }
}

const registerUser = asyncHandler( async (req, res) => {

    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const {fullname, email, username, password} = req.body;
    console.log("email", email);

    if(
        [fullname, email, username, password].some((field) => 
        field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = User.findOne({
        $or: [{username}, {email}]
    })

    if(existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }

    const avatarLocalPath = req.file?.avatar[0]?.path;
    const coverImageLocalPath = req.file?.coverImage[0]?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const user = User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser) {
        throw new ApiError(500, "Something went wrong when creating user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )
})

const logInUser = asyncHandler(async (req, res) =>{

    // req body => data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie

    const {email, username, password} = req.body;

    if(!(username || email) ){
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    });

    if(!user){
        throw new ApiError(400, "User does not found");
    }

    const ispasswordValid = await User.isPasswordCorrect(password);

    if(!ispasswordValid){
        throw new ApiError(400, "User does not found");
    }

    const {accessToken, refreshToken} = await generateAccessandRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).
        select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken, options) // cookie can be accesed through request
    .cookie("refreshToken", refreshToken, options) // req.cookie
    .json(
        new ApiResponse(
            200, // status code
            { // data
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully" // message
        )
    )

 })

 const logOutUser = asyncHandler(async(req, res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(
        new ApiResponse(
            200,
            {
                
            }
        )

    )

})

const refreshAccessToken = asyncHandler(async(req, res) => {

    try{

    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    
    if(!incomingRefreshToken){
        throw new ApiError(401, 'unauthorized request');
    }

    const decodedToken = jwt.verify(
        incomingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET
    )

    const user = await User.findById(decodedToken._id);

    if(!user){
        throw new ApiError(401, "Invalid Refresh Token")
    }

    if(incomingRefreshToken !== user?.refreshToken) {
        throw new ApiError(401, "Refresh Token is expired or Used")
    }

    const options = {
        httpOnly: true,
        secure: true,
    }

    const {accessToken, newRefreshToken} = await generateAccessandRefreshTokens(user._id)

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    }catch(error){
        throw new ApiError(401, error?.message || "Invalid token refreshed")
    }
})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)

    const isPassCorrect = await user.isPasswordCorrect(oldPassword);

    if(! isPassCorrect) {
        throw new ApiError(400, "Invalid old password");
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"))

})

const getCurrentUser = asyncHandler(async (req, res) => {

    return res
        .status(200)
        .json(200, req.user, "Current User fetched successfully");
})

const updateAccountDetails = asyncHandler(async(req, res) => {

    const {fullname, email} = req.body

    if(!fullname || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
           $set: {
            fullname,
            email: email
           } 
        },
        {new: true}
    ).select("-password")

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Account Details updated successfully"))
})

// Remember when writing controllers for file updation always write different controllers
const updateUserAvater = asyncHandler(async(req, res)=>{

    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
        .status(200)
        .json(new ApiResponse(200, user, 'Avater Updated successfully'))
})

const updateUserCoverImage = asyncHandler(async(req, res)=>{

    const coverImageLocalPath = req.file?.path

    if(! coverImageLocalPath) {
        throw new ApiError(400, "Cover Image is Missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(coverImage.url){
        throw new ApiError(400, "Error uploading an Image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {new: true}
    )

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "Cover Image updated successfully")
        )

})

export {registerUser, 
    logInUser, 
    logOutUser, 
    refreshAccessToken, 
    changeCurrentPassword, 
    getCurrentUser,
    updateAccountDetails,
    updateUserAvater,
    updateUserCoverImage
}