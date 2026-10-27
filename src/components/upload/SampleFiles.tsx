import { useState } from 'react';
import {
  createSampleFile,
  isSampleAvailable,
  SAMPLES,
  type SampleDefinition,
} from '../../features/samples/samplePdfs';

interface SampleFilesProps {
  readonly onFileSelected: (file: File) => void;
}

/** Lets people try the scanner with harmless, synthetic PDFs generated in the browser. */
export function SampleFiles({ onFileSelected }: SampleFilesProps) {
  const [error, setError] = useState<string | null>(null);
  const samples = SAMPLES.filter(isSampleAvailable);

  const choose = (sample: SampleDefinition) => {
    setError(null);
    createSampleFile(sample).then(onFileSelected, () => {
      setError('The sample could not be created in this browser.');
    });
  };

  return (
    <section className="samples" aria-labelledby="samples-heading">
      <h2 id="samples-heading" className="samples__title">
        No suspicious PDF at hand?
      </h2>
      <p className="samples__intro">
        Try a harmless sample. It is generated in your browser and scanned like any other file.
      </p>
      <ul className="samples__list">
        {samples.map((sample) => (
          <li key={sample.id}>
            <button
              type="button"
              className={`sample-button sample-button--${sample.id}`}
              onClick={() => {
                choose(sample);
              }}
            >
              <span className="sample-button__title">{sample.title}</span>
              <span className="sample-button__description">{sample.description}</span>
            </button>
          </li>
        ))}
      </ul>
      {error !== null && (
        <p className="samples__error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
