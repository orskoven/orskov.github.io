import React, { useState, useEffect, lazy, Suspense } from 'react';

// Components are lazily loaded to improve initial load performance
const ExpandableSection = lazy(() => import('./ExpandableSection'));
const FactBox = lazy(() => import('./FactBox'));
const ExternalLink = lazy(() => import('./ExternalLink'));

const fetchPostData = () => {
  // This function would ideally fetch data from an API
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve({
        title: 'Innovative Cybersecurity Insights by Tom at V2 Security',
        author: 'Simon Ø. D. Beckmann',
        date: 'May 1, 2024',
        url: 'https://master.d2p1vjkxtgfh0z.amplifyapp.com',
        paragraphs: [
          'During the recent V2 Security conference, keynote speaker Tom discussed several critical points about cybersecurity practices and philosophy, highlighting the need for innovative and practical measures.',
          'Tom emphasized the importance of protecting access cards by randomizing numbers to prevent hacking. He criticized the high costs associated with threat intelligence, necessary for red team operations, advocating for more affordable solutions.',
          'He questioned the frequency of attacks on organizations, noting the lack of solid data and suggested using canary tokens on the dark web as proactive detectors of planned attacks against companies.',
          'Tom also pointed out the over-reliance on third-party vendors for malware scanning, which often use similar services, thus not diversifying security practices enough.',
          'Discussing insider threats, Tom highlighted the lack of technical skills among many CISOs, which hinders effective cybersecurity management. He urged companies to foster a stronger culture of security, focusing on practical, human-centric training methods.',
          'Lastly, Tom advocated for "gaining home court advantage" by leveraging employees’ intimate knowledge of their own company to strengthen security measures from the inside out, encouraging innovation in security practices by understanding attacks from an inside perspective.'
        ],
        links: [
          { href: 'https://www.tomvdw.com', text: 'Learn more about Tom' }
        ],
        factBoxes: [
          { title: 'Key Fact', content: 'Effective cybersecurity involves both technical measures and organizational culture changes.' }
        ]
      });
    }, 1000);
  });
};

const Post5 = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [postContent, setPostContent] = useState({});

  useEffect(() => {
    fetchPostData().then(data => {
      setPostContent(data);
      setIsLoading(false);
    }).catch(() => {
      setError('Failed to fetch post data');
      setIsLoading(false);
    });
  }, []);

  if (isLoading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <section className="section">
      <h2>{postContent.title}</h2>
      <h5>Published on {postContent.date} by <a href={postContent.url}>{postContent.author}</a></h5>
      <Suspense fallback={<div>Loading content...</div>}>
        {postContent.paragraphs?.map((paragraph, index) => (
          <ExpandableSection key={index} content={paragraph} />
        ))}
        {postContent.links?.map(link => (
          <ExternalLink key={link.href} href={link.href} text={link.text} />
        ))}
        {postContent.factBoxes?.map((fact, index) => (
          <FactBox key={index} title={fact.title} content={fact.content} />
        ))}
      </Suspense>
    </section>
  );
};

export default Post5;