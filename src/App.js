import React, { useState, useEffect } from 'react';
import Toolbar from './Toolbar'; // Adjust path if necessary, assuming it's in the same directory
import Post1 from './Post1';
import Post2 from './Post2';
import Post3 from './Post3';
import Post4 from './Post4';
import Post5 from './Post5';
import Post6 from './Post6';
import Post7 from './Post7';
import Post8 from './Post8';
import Post9 from './Post9';
import Post10 from './Post10';
import Post11 from './Post11';

const posts = [
  { id: 1, component: <Post1 />, title: "Post Title 1" },
  { id: 2, component: <Post2 />, title: "Post Title 2" },
  { id: 3, component: <Post3 />, title: "Post Title 3" },
  { id: 4, component: <Post4 />, title: "Post Title 4" },
  { id: 5, component: <Post5 />, title: "Post Title 5" },
  { id: 6, component: <Post6 />, title: "Post Title 6" },
  { id: 7, component: <Post7 />, title: "Post Title 7" },
  { id: 8, component: <Post8 />, title: "Post Title 8" },
  { id: 9, component: <Post9 />, title: "Post Title 9" },
  { id: 10, component: <Post10 />, title: "Post Title 10" },
  { id: 11, component: <Post11 />, title: "Post Title 11" },
];

const App = () => {
  const [filteredPosts, setFilteredPosts] = useState(posts);
  const [searchTerm, setSearchTerm] = useState('');

  const handleSearchChange = (event) => {
    const term = event.target.value;
    setSearchTerm(term);
    if (term === '') {
      setFilteredPosts(posts);
    } else {
      const filtered = posts.filter(post => post.title.toLowerCase().includes(term.toLowerCase()));
      setFilteredPosts(filtered);
    }
  };

  return (
    <div className="App">
      <Toolbar />
      <input
        type="text"
        value={searchTerm}
        onChange={handleSearchChange}
        placeholder="Search posts by title..."
        style={{ margin: '10px', padding: '5px', width: '95%' }}
      />
      <div className="content">
        {filteredPosts.length > 0 ? (
          filteredPosts.map(post => (
            <div key={post.id}>
              {post.component}
            </div>
          ))
        ) : (
          <p>No posts match your search criteria.</p>
        )}
      </div>
    </div>
  );
};

export default App;