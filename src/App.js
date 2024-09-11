import React from 'react';
import Toolbar from './Toolbar';
import Post1 from './Post1';
import Post2 from './Post2';
import Post3 from './Post3';
import Post4 from './Post4';
import Post12 from './Post12';
import Post6 from './Post6';
import Post7 from './Post7';
import Post8 from './Post8';
import Post10 from './Post10';
import Post11 from './Post11';
import Post13 from './Post13';
import MainTable from './Post20';

import './App.css';

const App = () => {
  return (
    <div className="App">
      <Toolbar />
      <main className="content">
        <MainTable />
        <Post13 />
        <Post12 />
        <Post11 />
        <Post10 />
        <Post8 />
        <Post7 />
        <Post6 />

        <Post4 />
        <Post3 />
        <Post2 />
        <Post1 />
      </main>
    </div>
  );
};

export default App;
