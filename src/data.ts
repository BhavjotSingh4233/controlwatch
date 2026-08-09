// We are exporting this variable so other files in our project
// can import and use the same employee data.

export const users = [
	{
		id: 1,
		name: "Alice",
		role: "admin",
		mfa: true,
		active: true,
	},
	{
		id: 2,
		name: "Bob",
		role: "admin",
		mfa: false,
		active: true,
	},
	{
		id: 3,
		name: "Carol",
		role: "employee",
		mfa: false,
		active: true,
	},
];