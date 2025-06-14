'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import './page.css';
interface Course {
  courseId: string;
  title: string;
  instructormail: string;
  instructorName?: string;
  description: string;
  category: string;
  difficultyLevel: 'Beginner' | 'Intermediate' | 'Advanced';
  isArchived: boolean;
  totalClasses: number;
  courseContent: string[]; // Array of PDF URLs/paths
  notes: string[]; // Array of note IDs or content (you can adjust depending on the structure of the notes)
  price: number;
  image: string; // URL or path to the course image
  Point_Based: boolean; // If true, only instructors can access the course
}

const RegisterPage = () => {
  const [name, setName] = useState('');
  const [age, setAge] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [selectedCourses, setSelectedCourses] = useState<string[]>([]);
  const [profilePictureUrl, setprofilePictureUrl] = useState<string | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [Courses, setCourses] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  useEffect(() => {
    fetchCourses();
  }, []);
  // Handle course selection
  const handleCourseChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    setSelectedCourses(
      (prevSelectedCourses) =>
        event.target.checked
          ? [...prevSelectedCourses, value] // Add course if checked
          : prevSelectedCourses.filter((course) => course !== value), // Remove course if unchecked
    );
  };
  const fetchCourses = async (): Promise<string[]> => {
    try {
      setIsLoading(true);
      const response = await fetch(
        `http://localhost:3000/courses/CoursesTitle`,
        {
          method: 'GET',
        },
      );

      if (!response.ok) {
        throw new Error(`Failed to fetch user details: ${response.statusText}`);
      }

      const coursesTitle = await response.json();
      console.log('Fetched courses details:', coursesTitle); // Debugging: Log the fetched user details
      setCourses(coursesTitle);
      return coursesTitle; // Update state with user data
    } catch (error) {
      console.error('Error fetching user details', error);
      throw error; // Propagate the error for the caller to handle
    } finally {
      setIsLoading(false);
    }
  };

  // Handle image selection
  const handleImageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        setprofilePictureUrl(reader.result as string); // Convert image to Base64 URL
      };
      reader.readAsDataURL(file);
    }
  };

  // Handle form submission
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    // Basic validation
    if (!name || !age || !email || !password || !confirmPassword) {
      setError('All fields are required');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      // API call to register
      const response = await fetch('http://localhost:3000/users/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name,
          age,
          email,
          passwordHash: password,
          appliedCourses: selectedCourses,
          profilePictureUrl, // Send the Base64 URL of the image
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to register');
      }

      // Clear the error and redirect to home
      setError(null);
      router.push('/login'); // Redirect to the login page
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    }
  };

  return (
    <form className="form" onSubmit={handleSubmit}>
      <p className="title">Register</p>
      <p className="message">Signup now and get full access to our app.</p>

      <div className="flex">
        {/* Name and Age Fields */}
        <label>
          <input
            required
            type="text"
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <span>Name</span>
        </label>
        <label>
          <input
            required
            type="number"
            className="input"
            value={age}
            onChange={(e) => setAge(e.target.value)}
          />
          <span>Age</span>
        </label>
      </div>

      {/* Email and Password Fields */}
      <label>
        <input
          required
          type="email"
          className="input"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <span>Email</span>
      </label>
      <label>
        <input
          required
          type="password"
          className="input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <span>Password</span>
      </label>
      <label>
        <input
          required
          type="password"
          className="input"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
        />
        <span>Confirm Password</span>
      </label>

      {/* Profile Picture Upload */}
      <label className="file-upload">
        <input type="file" accept="image/*" onChange={handleImageChange} />
        <span>Upload Profile Picture</span>
      </label>
      {profilePictureUrl && (
        <div className="image-preview">
          <p>Image Preview:</p>
          <img
            src={profilePictureUrl}
            alt="profilePictureUrl"
            className="circular-preview"
          />
        </div>
      )}

      {/* Course Selection with Checkboxes */}
      <div className="courses">
        <p>Courses to Apply:</p>

        {isLoading ? (
          // Loading spinner or animation
          <div className="loading-container">
            <i className="loading-icon" />
            <strong>Loading , please wait...</strong>
          </div>
        ) : (
          // Render courses when loading is complete
          Courses.map((course, index) => (
            <label key={index}>
              <input
                type="checkbox"
                name="course"
                value={course}
                checked={selectedCourses.includes(course)}
                onChange={handleCourseChange}
              />
              <span>{course}</span>
            </label>
          ))
        )}
      </div>
      {/* Show error message if there's any */}
      {error && <p className="error-message">{error}</p>}

      {/* Submit Button */}
      <button type="submit" className="submit">
        Submit
      </button>

      {/* Signin Link */}
      <p className="signin">
        Already have an account? <a href="/login">Signin</a>
      </p>
    </form>
  );
};

export default RegisterPage;
